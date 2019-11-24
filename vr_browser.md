# The outdated and vulnerable browser in Virtual Reality games

My labmate works hard to address the safety issues in the Virtual Reality world. 
Out of curiosity, I looked at one of the popular VR social game, AltspaceVR. 

In the VR world, there are virtual theaters and virtual TVs - you can watch YouTube videos through the eye of the avatars.
![VR browser](pic/vr1.png)
To achieve this, the game embeds a browser. 

And to my surprise, I found out that the browser is a two years old Chrome 62, originally released in October 2017.
The stale browser is alarming because we have seen many browser vulnerabilities, such as the [WebGL bugs](https://trusslab.github.io/sugar/webgl_bugs.html).
I haven't run any PoCs, but it is easy to imagine that missing this amount of patches means a lot of web app privilege escalations and crashes can happen. 
As a conclusion, you should only load trustworthy websites in the VR browsers.

I would suggest not to host a separate Chrome in VR games, but to simply run the default browser installed on the machine, and redirect the browser's framebuffer into the game.
We have done this in one of our previous research, [Sugar](https://www.ics.uci.edu/~ardalan/papers/Yao_ASPLOS18.pdf), and our code is [open source](https://github.com/trusslab/sugar_chromium).
![VR browser](pic/vr2.png)
