# RDS-SECURITY-SYSTEM
The RDS security system allows connection only through specific computers that are predefined as authorized computers.

The only requirement from the client is that the script will always run in the background, without any intervention from his side.
The script will be run in the initial configuration of the client computer, in that way it will start automatically when the computer is turned on.

First of all, the only access to the RDS servers will be through a script located in the RDS router.

The script forwards to the RDS only approved messages.

The approval process works as follows:
1. For each package that sent from the client to the RDS server, a message is sent via the client script confirming the package.
2. Once the script in the router detects a certain amount of unapproved packages, it blocks communication with this end-user.
3. As long as the script in the router receives approval messages from the client's script there is full access for that end-user.

The process of approving the package:
1. The router's script takes from each packet coming to the RDS serve its TCP layer and up (the load) and calculat for it is HASH256.
2. At the same time, the client-side script also does the same process, i.e. takes its TCP layer and up (the load) from each packet and passes this information in the HASH256 function.
3. The client-side script sends the result from the previous line to the router's script at a specific port.
4. The router's script receives these certificate packets and compares the hash it receives to the hash it has calculated, similar to a digital signature.
5. Once there is more than a certain amount of messages that do not pass this confirmation, the router blocks the communication with that client.

The whole process is encrypted from end to end.
The symmetrical keys are exchanged using a pair of asymmetrical keys.
Between each client and server, there is a key renewal every few minutes.

The process simulates a digital signature on each package sent to RDS.

server.py - This is the server's script. It prevents access to RDS from unauthorized computers.

client.py - This is the client's script. It sends authentication packets to all packets sent to RDS from the client.
