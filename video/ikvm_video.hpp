/* SPDX-License-Identifier: GPL-2.0-or-later */

#pragma once

#include <mutex>
#include <string>
#include <vector>
#include <map>
#include <linux/videodev2.h>

#define pr_dbg(fmt, args...) printf("%s(): " fmt, __func__, ## args)
#define V4L2_PIX_FMT_AJPG     v4l2_fourcc('A', 'J', 'P', 'G')


namespace ikvm
{

/*
 * @class Video
 * @brief Sets up the V4L2 video device and performs read operations
 */
class Video
{
  public:
    /*
     * @brief Constructs Video object
     *
     * @param[in] p     - Path to the V4L2 video device
     * @param[in] fr    - desired frame rate of the video
     */
    Video(int i = 0, int fr = 30, int q = 4, int sub = 0, int fmt = 0);
    ~Video();
    Video(const Video&) = default;
    Video& operator=(const Video&) = default;
    Video(Video&&) = default;
    Video& operator=(Video&&) = default;

    /*
     * @brief Gets the video frame data
     *
     * @return Pointer to the video frame data
     */
    char* getData();
    /* @brief Performs read to grab latest video frame */
    int getFrame();
    /*
     * @brief Gets whether or not the video frame needs to be resized
     *
     * @return Boolean indicating if the frame needs to be resized
     */
    bool needsResize();
    /* @brief Performs the resize and re-allocates framebuffer */
    int resize();
    /* @brief Starts streaming from the video device */
    int start();
    /* @brief Stops streaming from the video device */
    int stop();
    /* @brief Restarts streaming from the video device */
    int restart()
    {
        stop();
        return start();
    }
    /* @brief set the input of the video to capture */
    void setInput(int input);
    /* @brief set the size of input, aspeed test only */
    void setInputSize(int width, int height);
    /* @brief get input buffer address of the video, aspeed test only */
    void getInputBuffer(unsigned char **addr);
    /* @brief trigger capture, aspeed test only */
    void capture();

    /*
     * @brief Gets the desired video frame rate in frames per second
     *
     * @return Value of the desired frame rate
     */
    inline int getFrameRate() const
    {
        return frameRate;
    }
    inline void setFrameRate(int fr)
    {
        frameRate = fr;
    }
    /*
     * @brief Gets the size of the video frame data
     *
     * @return Value of the size of the video frame data in bytes
     */
    inline size_t getFrameSize() const
    {
        return buffers[lastFrameIndex].payload;
    }
    /*
     * @brief Gets the height of the video frame
     *
     * @return Value of the height of video frame in lines
     */
    inline size_t getHeight() const
    {
        return height;
    }
    /*
     * @brief Gets the width of the video frame
     *
     * @return Value of the width of video frame in pixels
     */
    inline size_t getWidth() const
    {
        return width;
    }
    /*
     * @brief Gets the video frame count in sequence
     *
     * @return Value of video frame count in sequence
     */
    inline size_t getFrameNumber() const
    {
        return buffers[lastFrameIndex].sequence;
    }
    /*
     * @brief Gets the quality of the video frame
     *
     * @return Value of the quality of video frame
     */
    inline int getQuality() const
    {
        return jpegQuality;
    }
    /*
     * @brief Sets the jpeg format of the video frame
     *
     */
    inline void setQuality(int _quality)
    {
        jpegQuality = _quality;
    }
    /*
     * @brief Gets the subsampling of the video frame
     *
     * @return Value of the subsampling of video frame, 1:420/0:444
     */
    inline int getSubsampling() const
    {
        return jpegSubSampling;
    }
    /*
     * @brief Sets the subsampling of the video frame
     *
     */
    inline void setSubsampling(int _sub)
    {
        jpegSubSampling = _sub;
    }
    /*
     * @brief Gets the jpeg format of the video frame
     *
     * @return Value of the jpeg format of video frame
     *         0:standard jpeg, 1:aspeed, 2:partial
     */
    inline int getFormat() const
    {
        return format;
    }
    /*
     * @brief Sets the jpeg format of the video frame
     *
     */
    inline void setFormat(int _fmt)
    {
        format = _fmt;
    }
    /*
     * @brief Gets the HQ Mode of compression
     *
     * @return Value of the HQ Mode
     */
    inline bool getHQMode() const
    {
        return aspeedHQMode;
    }
    /*
     * @brief Sets the HQ Mode of compression
     *
     */
    inline void setHQMode(bool mode)
    {
        aspeedHQMode= mode;
    }
    /*
     * @brief Gets the hq quality of the video frame
     *
     * @return Value of the quality of video frame
     */
    inline int getHQuality() const
    {
        return aspeedHQuality;
    }
    /*
     * @brief Sets the jpeg format of the video frame
     *
     */
    inline void setHQuality(int _quality)
    {
        aspeedHQuality = _quality;
    }

    inline void setID(int _id)
    {
        instId = _id;
    }

  private:
    /*
     * @brief find v4l2 ctrl-id by the given name
     *
     * @param[in] name  - v4l2 ctrl name
     * @return v4l2 ctrl-id if found, but 0 if not found.
     */
    int common_find_ctrl_id(const char *name);

    /*
     * @struct Buffer
     * @brief Store the address and size of frame data from streaming
     *        operations
     */
    struct Buffer
    {
        Buffer() : data(nullptr), queued(false), payload(0), size(0)
        {
        }
        ~Buffer() = default;
        Buffer(const Buffer&) = default;
        Buffer& operator=(const Buffer&) = default;
        Buffer(Buffer&&) = default;
        Buffer& operator=(Buffer&&) = default;

        void* data;
        bool queued;
        size_t payload;
        size_t size;
        uint32_t sequence;
    };

    int instId;
    /*
     * @brief Boolean to indicate whether the resize was triggered during
     *        the open operation
     */
    bool resizeAfterOpen;
    /* @brief Indicates whether or not timings query was last sucessful */
    bool timingsError;
    /* @brief File descriptor for the V4L2 video device */
    int fd;
    /* @brief Desired frame rate of video stream in frames per second */
    int frameRate;
    /* @brief Buffer index for the last video frame */
    int lastFrameIndex;
    /* @brief Height in lines of the video frame */
    size_t height;
    /* @brief Width in pixels of the video frame */
    size_t width;
    /* @brief jpeg's quality (0~11) */
    int jpegQuality;
    /* @brief jpeg's subsampling, 1:420/0:444 */
    int jpegSubSampling;
    /* @brief aspeed's jpeg format, which support partial update */
    int format;
    /* @brief aspeed's hq mode, only for 444 subsampling
     * It can have better quality for static video by 2-pass video compression scheme
     */
    bool aspeedHQMode;
    /* @brief aspeed's hq quality, (1~12)
     */
    bool aspeedHQuality;
    /* @brief Streaming buffer storage */
    std::vector<Buffer> buffers;
    /* @brief map of ctrl and its name */
    std::map<std::string, struct v4l2_queryctrl> ctrl_str2q;
    /* @brief input of the capture. 0: vga, 1:gfx, 2:memory */
    int input;
    /* @brief Width in pixels of the dbg video frame from memory, only useful if input is 2 */
    size_t dbg_width;
    /* @brief Height in lines of the dbg video frame from memory, only useful if input is 2 */
    size_t dbg_height;
};

} // namespace ikvm
