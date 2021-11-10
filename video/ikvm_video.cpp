#include "ikvm_video.hpp"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <iostream>



namespace ikvm
{

Video::Video(const std::string& p, int fr, int q, int sub, int fmt) :
    resizeAfterOpen(false), timingsError(false), fd(-1), frameRate(fr),
    lastFrameIndex(-1), height(600), width(800),
    jpegQuality(q), jpegSubSampling(sub), format(fmt), aspeedHQMode(false),
    path(p)
{
    v4l2_queryctrl qctrl;

    fd = open(path.c_str(), O_RDWR);
    if (fd < 0)
    {
        pr_dbg("Failed to open video device PATH=%s ERROR=%s\n",
               path.c_str(), strerror(errno));
    }

    qctrl.id = V4L2_CTRL_FLAG_NEXT_CTRL;
    while (ioctl(fd, VIDIOC_QUERYCTRL, &qctrl) == 0) {
        if (qctrl.type == V4L2_CTRL_TYPE_CTRL_CLASS) {
            pr_dbg("[%-30s]\n", qctrl.name);
        } else {
            ctrl_str2q[std::string((char *)qctrl.name)] = qctrl;
            pr_dbg("%-30s : type=%d, minimum=%d, maximum=%d, step=%d, default_value=%d\n",
                   qctrl.name, qctrl.type, qctrl.minimum, qctrl.maximum,
                   qctrl.step, qctrl.default_value);
        }

        qctrl.id |= V4L2_CTRL_FLAG_NEXT_CTRL;
    }

    close(fd);
    fd = -1;
}

Video::~Video()
{
    stop();
}

char* Video::getData()
{
    if (lastFrameIndex >= 0)
    {
        return (char*)buffers[lastFrameIndex].data;
    }

    return nullptr;
}

int Video::common_find_ctrl_id(const char *name)
{
    std::string s = std::string(name);

    if (ctrl_str2q.find(s) == ctrl_str2q.end())
        return 0;
    return ctrl_str2q[s].id;
}

int Video::getFrame()
{
    int rc(0);
    int fd_flags;
    v4l2_buffer buf;
    fd_set fds;
    timeval tv;
    bool valid_frame(false);

    if (fd < 0)
    {
        return -1;
    }

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    memset(&buf, 0, sizeof(v4l2_buffer));
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;

    // Switch to non-blocking in order to safely dequeue all buffers; if the
    // video signal is lost while blocking to dequeue, the video driver may
    // wait forever if signal is not re-acquired
    fd_flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fd_flags | O_NONBLOCK);

    rc = select(fd + 1, &fds, NULL, NULL, &tv);
    if (rc > 0)
    {
        do
        {
            rc = ioctl(fd, VIDIOC_DQBUF, &buf);
            if (rc >= 0)
            {
                buffers[buf.index].queued = false;

                if (!(buf.flags & V4L2_BUF_FLAG_ERROR))
                {
                    lastFrameIndex = buf.index;
                    buffers[lastFrameIndex].payload = buf.bytesused;
                    buffers[buf.index].sequence = buf.sequence;
                    valid_frame = true;
                    break;
                }
                else
                {
                    buffers[buf.index].payload = 0;
                }
            }
        } while (rc >= 0);
    } else {
        pr_dbg("select failed ERROR=%s\n", strerror(errno));
        return -1;
    }

    fcntl(fd, F_SETFL, fd_flags);

    for (unsigned int i = 0; i < buffers.size(); ++i)
    {
        if (i == (unsigned int)lastFrameIndex)
        {
            continue;
        }

        if (!buffers[i].queued)
        {
            memset(&buf, 0, sizeof(v4l2_buffer));
            buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
            buf.memory = V4L2_MEMORY_MMAP;
            buf.index = i;

            rc = ioctl(fd, VIDIOC_QBUF, &buf);
            if (rc)
            {
                pr_dbg("Failed to queue buffer ERROR=%s\n", strerror(errno));
            }
            else
            {
                buffers[i].queued = true;
            }
        }
    }

    return valid_frame ? 0 : -1;
}

bool Video::needsResize()
{
    int rc, count = 0;
    v4l2_dv_timings timings;

    if (fd < 0)
    {
        return false;
    }

    if (resizeAfterOpen)
    {
        return true;
    }

    memset(&timings, 0, sizeof(v4l2_dv_timings));
    // try more times if failed
    do {
        rc = ioctl(fd, VIDIOC_QUERY_DV_TIMINGS, &timings);
        if (rc < 0) {
            usleep(200 * 1000);
        } else
            break;
    } while (count++ < 10);

    if (rc < 0)
    {
        if (!timingsError)
        {
            pr_dbg("Failed to query timings ERROR=%s\n", strerror(errno));
            timingsError = true;
        }

        restart();
        return false;
    }

    timingsError = false;

    if (timings.bt.width != width || timings.bt.height != height)
    {
        pr_dbg("timing old(%dx%d) new(%dx%d)\n", width, height, timings.bt.width, timings.bt.height);
        width = timings.bt.width;
        height = timings.bt.height;

        if (!width || !height)
        {
            pr_dbg("Failed to get new resolution WIDTH=%d, HEIGHT=%d\n", width, height);
        }

        lastFrameIndex = -1;
        return true;
    }

    return false;
}

int Video::resize()
{
    int rc;
    unsigned int i;
    bool needsResizeCall(false);
    v4l2_buf_type type(V4L2_BUF_TYPE_VIDEO_CAPTURE);
    v4l2_requestbuffers req;

    if (fd < 0)
    {
        return -1;
    }

    if (resizeAfterOpen)
    {
        resizeAfterOpen = false;
        return 0;
    }

    for (i = 0; i < buffers.size(); ++i)
    {
        if (buffers[i].data)
        {
            needsResizeCall = true;
            break;
        }
    }

    if (needsResizeCall)
    {
        rc = ioctl(fd, VIDIOC_STREAMOFF, &type);
        if (rc)
        {
            pr_dbg("Failed to stop streaming ERROR=%s\n", strerror(errno));
        }
    }

    for (i = 0; i < buffers.size(); ++i)
    {
        if (buffers[i].data)
        {
            munmap(buffers[i].data, buffers[i].size);
            buffers[i].data = nullptr;
            buffers[i].queued = false;
        }
    }

    if (needsResizeCall)
    {
        v4l2_dv_timings timings;

        memset(&req, 0, sizeof(v4l2_requestbuffers));
        req.count = 0;
        req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        req.memory = V4L2_MEMORY_MMAP;
        rc = ioctl(fd, VIDIOC_REQBUFS, &req);
        if (rc < 0)
        {
            pr_dbg("Failed to zero streaming buffers ERROR=%s\n", strerror(errno));
        }

        memset(&timings, 0, sizeof(v4l2_dv_timings));
        rc = ioctl(fd, VIDIOC_QUERY_DV_TIMINGS, &timings);
        if (rc < 0)
        {
            pr_dbg("Failed to query timings ERROR=%s\n", strerror(errno));
            return -1;
        }

        rc = ioctl(fd, VIDIOC_S_DV_TIMINGS, &timings);
        if (rc < 0)
        {
            pr_dbg("Failed to set timings ERROR=%s\n", strerror(errno));
            return -1;
        }

        buffers.clear();
    }

    memset(&req, 0, sizeof(v4l2_requestbuffers));
    req.count = 3;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    rc = ioctl(fd, VIDIOC_REQBUFS, &req);
    if (rc < 0 || req.count < 2)
    {
        pr_dbg("Failed to request streaming buffers ERROR=%s\n", strerror(errno));
        return -1;
    }

    buffers.resize(req.count);

    for (i = 0; i < buffers.size(); ++i)
    {
        v4l2_buffer buf;

        memset(&buf, 0, sizeof(v4l2_buffer));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;

        rc = ioctl(fd, VIDIOC_QUERYBUF, &buf);
        if (rc < 0)
        {
            pr_dbg("Failed to query buffer ERROR=%s\n", strerror(errno));
        }

        buffers[i].data = mmap(NULL, buf.length, PROT_READ | PROT_WRITE,
                               MAP_SHARED, fd, buf.m.offset);
        if (buffers[i].data == MAP_FAILED)
        {
            pr_dbg("Failed to mmap buffer ERROR=%s\n", strerror(errno));
            return -1;
        }

        buffers[i].size = buf.length;

        rc = ioctl(fd, VIDIOC_QBUF, &buf);
        if (rc < 0)
        {
            pr_dbg("Failed to queue buffer ERROR=%s\n", strerror(errno));
            return -1;
        }

        buffers[i].queued = true;
    }

    rc = ioctl(fd, VIDIOC_STREAMON, &type);
    if (rc)
    {
        pr_dbg("Failed to start streaming ERROR=%s\n", strerror(errno));
    }
    return rc;
}

int Video::start()
{
    int rc;
    size_t oldHeight = height;
    size_t oldWidth = width;
    v4l2_capability cap;
    v4l2_format fmt;
    v4l2_streamparm sparm;
    v4l2_control ctrl;

    if (fd >= 0)
    {
        return 0;
    }

    fd = open(path.c_str(), O_RDWR);
    if (fd < 0)
    {
        pr_dbg("Failed to open video device PATH=%s ERROR=%s\n",
               path.c_str(), strerror(errno));
        return -1;
    }

    memset(&cap, 0, sizeof(v4l2_capability));
    rc = ioctl(fd, VIDIOC_QUERYCAP, &cap);
    if (rc < 0)
    {
        pr_dbg("Failed to query video device capabilities ERROR=%s\n", strerror(errno));
    }

    if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) ||
        !(cap.capabilities & V4L2_CAP_STREAMING))
    {
        pr_dbg("Video device doesn't support this application\n");
        return -1;
    }

    memset(&fmt, 0, sizeof(v4l2_format));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    rc = ioctl(fd, VIDIOC_G_FMT, &fmt);
    if (rc < 0)
    {
        pr_dbg("Failed to query video device format ERROR=%s\n", strerror(errno));
    }

    fmt.fmt.pix.pixelformat = format ? V4L2_PIX_FMT_AJPG : V4L2_PIX_FMT_JPEG;
    rc = ioctl(fd, VIDIOC_S_FMT, &fmt);
    if (rc < 0)
    {
        pr_dbg("Failed to set video device format ERROR=%s\n", strerror(errno));
    }

    memset(&sparm, 0, sizeof(v4l2_streamparm));
    sparm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    sparm.parm.capture.timeperframe.numerator = 1;
    sparm.parm.capture.timeperframe.denominator = frameRate;
    rc = ioctl(fd, VIDIOC_S_PARM, &sparm);
    if (rc < 0)
    {
        pr_dbg("Failed to set video device frame rate ERROR=%s\n", strerror(errno));
    }

    ctrl.id = V4L2_CID_JPEG_COMPRESSION_QUALITY;
    ctrl.value = jpegQuality;
    rc = ioctl(fd, VIDIOC_S_CTRL, &ctrl);
    if (rc < 0)
    {
        pr_dbg("Failed to set video jpeg quality ERROR=%s\n", strerror(errno));
    }

    ctrl.id = V4L2_CID_JPEG_CHROMA_SUBSAMPLING;
    ctrl.value = jpegSubSampling
	       ? V4L2_JPEG_CHROMA_SUBSAMPLING_420 : V4L2_JPEG_CHROMA_SUBSAMPLING_444;
    rc = ioctl(fd, VIDIOC_S_CTRL, &ctrl);
    if (rc < 0)
    {
        pr_dbg("Failed to set video jpeg subsampling ERROR=%s\n", strerror(errno));
    }

    if ((ctrl.id = common_find_ctrl_id("Aspeed HQ Mode")) != 0) {
        ctrl.value = aspeedHQMode;
        rc = ioctl(fd, VIDIOC_S_CTRL, &ctrl);
        if (rc < 0)
        {
            pr_dbg("Failed to set video jpeg aspeed HQ mode ERROR=%s\n", strerror(errno));
        }
    }

    if ((ctrl.id = common_find_ctrl_id("Aspeed HQ Quality")) != 0) {
        ctrl.value = jpegQuality;
        rc = ioctl(fd, VIDIOC_S_CTRL, &ctrl);
        if (rc < 0)
        {
            pr_dbg("Failed to set video jpeg aspeed HQ Quality ERROR=%s\n", strerror(errno));
        }
    }

    height = fmt.fmt.pix.height;
    width = fmt.fmt.pix.width;

    rc = resize();

    if (oldHeight != height || oldWidth != width)
    {
        resizeAfterOpen = true;
    }
    return rc;
}

int Video::stop()
{
    int rc;
    unsigned int i;
    v4l2_buf_type type(V4L2_BUF_TYPE_VIDEO_CAPTURE);

    if (fd < 0)
    {
        return -1;
    }

    lastFrameIndex = -1;

    rc = ioctl(fd, VIDIOC_STREAMOFF, &type);
    if (rc)
    {
        pr_dbg("Failed to stop streaming ERROR=%s\n", strerror(errno));
        return -1;
    }

    for (i = 0; i < buffers.size(); ++i)
    {
        if (buffers[i].data)
        {
            munmap(buffers[i].data, buffers[i].size);
            buffers[i].data = nullptr;
            buffers[i].queued = false;
        }
    }

    close(fd);
    fd = -1;
    return 0;
}

} // namespace ikvm
