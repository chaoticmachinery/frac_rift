#!/usr/bin/python

from pypsexec.client import Client
import sys, getopt

version = 0.1

def main(argv):
   dest = ''
   user = ''
   passwd = ''
   cmd = ''
   cmdarg = ''
   encryptarg = False
   verbose = 0
   stdout = ''
   stderr = ''
   rc = ''
   
   try:
      opts, args = getopt.getopt(argv,"Vevd:u:p:c:a:",["dest=","user=","pass=","cmd=","cmdarg=","--verbose"])
   except getopt.GetoptError:
      print '%s -d <destination> -u <user> -p <pass> -c <cmd> -a <cmd arguements> -v {verbose} -e {Turns encryption on}' % sys.argv[0]
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print '%s -d <destination> -u <user> -p <pass> -c <cmd> -a <cmd arguements> -v {verbose} -e {Turns encryption on}' % sys.argv[0]
         sys.exit()
      elif opt in ("-d", "--dest"):
         dest = arg
      elif opt in ("-u", "--user"):
         user = arg
      elif opt in ("-p", "--pass"):
         passwd = arg
      elif opt in ("-c", "--cmd"):
         cmd = arg
      elif opt in ("-a", "--cmdarg"):
         cmdarg = arg
      elif opt in ("-e", "--encrypt"):
         encryptarg = True
      elif opt in ("-v", "--verbose"):
         verbose = 1
      elif opt in ("-V", "--Version"):
         print "Python Windows Exec"
         print "By Keven Murphy"
         print "Description: Python Windows Exec has the same main functionality as psexec."
         print "             Allows for remote launching of windows programs on a remote machine."
         print "Version: %s" % version
         sys.exit()
         
   # creates an encrypted connection to the host with the username and password
   #c = Client(dest, username=user, password=passwd,encrypt=encryptarg)
   c = Client(dest, username=user, password=passwd,encrypt=encryptarg)

   if verbose == 1:
       print "Destination: %s" % dest
       print "User: %s" % user
       print "Password: %s" % passwd
       print "CMD: %s" % cmd
       print "CMD Arguements: %s" %cmdarg
       print "Encrypt: %s" % encryptarg



   try:
       c.connect()
       c.create_service()

       # After creating the service, you can run multiple exe's without
       # reconnecting

       # run a simple cmd.exe program with arguments
       stdout, stderr, rc = c.run_executable(cmd,
                                          arguments=cmdarg)
       if verbose == 1:
          print
          print "STDOUT"
          print "======"
          print "%s" % stdout
          print
          print
          print "STDERR"
          print "======"
          print "%s" % stderr
          print
          print
          print "rc    : %s" % rc

       c.remove_service()
       c.disconnect()
   except:
          print "Timeout connecting"
          if verbose == 1:
             print
             print "STDOUT"
             print "======"
             print "%s" % stdout
             print
             print
             print "STDERR"
             print "======"
             print "%s" % stderr
             print
             print
             print "rc    : %s" % rc

if __name__ == "__main__":
   main(sys.argv[1:])





