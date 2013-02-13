//Packet Bouncer - IK2213
Roumpoutsos Nikolaos

In a more detailed description, our Packet Bouncer can be divided into 2 parts: an ICMP bouncer that
receives ICMP requests from a client , bounce the request to the server, then receive the ICMP reply
from the server and bounce back to the client. The same occurs in the case of a TCP bouncer. A client
is asking for a new TCP connection and the bouncer redirects the request to the server, receive server's
reply and bounce back to the client.

The purpose of this project is to implement a Packet Bouncer with the following features:
1.Bouncing ICMP requests-replies
2.Bouncing TCP connection requests