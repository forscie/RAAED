   ______     ______     ______     ______     _____    
  /\  == \   /\  __ \   /\  __ \   /\  ___\   /\  __-.  
  \ \  __<   \ \  __ \  \ \  __ \  \ \  __\   \ \ \/\ \ 
   \ \_\ \_\  \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \____- 
    \/_/ /_/   \/_/\/_/   \/_/\/_/   \/_____/   \/____/ 
                                                      
   [R]emote [A]ccess + [A]utomated [E]numeration [D]evice


The RAAED Client and Server scripts are designed to be enable a small device (RAAEDClient.py) to be placed
on a target network and create a clandestine reverse SSH session (impersonating HTTPS traffic on port 443) to
a remote server (RAAEDServer.py). In doing so, the RAAED device conducts remote enumeration of the target network,
whereby all hosts are detected and reported to the user on the server (through the SSH Tunnel) and displayed in a GUI.

The RAAED utilises SSH-RSA public/private key pairs in order to function. Additionally the RAAED requires
SSH services to be running on both the client and server. (port 443 - Server, port 22 - Client). Specific configuration
of each SSHD_config is required in order to permit SSH-RSA authentication.


     *These scripts should only be used for educational purposes, within the law.*
     Author: forScience james@forscience.xyz

