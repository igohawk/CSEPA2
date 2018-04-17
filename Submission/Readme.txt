*** Programming Assignment 2
*** Authors : Zeng Yueran (1002207), Li Xueqing(1002182)
*** Date: 18/04/2018


****************************************************

**********    How to run the program     ***********

****************************************************

Step 1. Download the code file and unzip it.
The zip file contains four java files (client and server programs for CP1 and CP2)

Step 2. Open ServerCP1.java (or ServerCP2.java) and ClientCP1.java (or ClientCP2.java) in two different devices. 
- change the signed certificate path (signedCertPath) and private key path (privateKeyPath) in server file, and change Certificate Authority's path (CACert)
- change the path of the file you want to send (FileName)
- change SERVER_NAME to the IP address of your server
- set the port number in client consistent with server's
- change the type and name of the received file

Step 3. Run the code. Run server file first, then client file
For Java IDE:
Create a new project and put all the java code into the main package. Then run java files using the IDE.

For Shell (Terminal):
 - Using "cd" command to change the directory to where the java code is.
	For Example: $ cd "/home/igoshawk/workspace/assignment2"
 - Using "javac" command to compile ServerCP1.java
	$ javac ServerCP1.java
 - Using "java" command to run ServerCP1.java
	$ java ServerCP1
All received files are in the same folder as the java files











