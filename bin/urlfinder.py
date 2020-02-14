import os
#import sys

import splunk.Intersplunk
import re

import logging
from logging.handlers import RotatingFileHandler
#from datetime import datetime

def setup_logging():
   """ initialize the logging handler """
   logger = logging.getLogger('splunk.urlfinder')
   SPLUNK_HOME = os.environ['SPLUNK_HOME']
   LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log.cfg')
   LOGGING_LOCAL_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log-local.cfg')
   LOGGING_STANZA_NAME = 'python'
   LOGGING_FILE_NAME = "urlfinder.log"
   BASE_LOG_PATH = os.path.join('var', 'log', 'splunk')
   LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - %(message)s"
   splunk_log_handler = logging.handlers.RotatingFileHandler(os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode='a')
   splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
   logger.addHandler(splunk_log_handler)
   splunk.setupSplunkLogger(logger, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME)
   return logger

logger = setup_logging()

def main():
  keywords,kvs = splunk.Intersplunk.getKeywordsAndOptions() # get parameters
  UFPRE = "uf_"
  DECODE = False
  FIELD = "_raw"

  if "nouf" in keywords:
    UFPRE = ""

  if "field" in kvs:
    FIELD = kvs["field"]

  if "decode" in keywords:
    DECODE = True
    import urllib

# check for method in _raw string

# make REGEX used variables
  #strex=ur"((?P<method>GET|POST)\s+(?P<url>\S+)(\s+(?P<protocol>\w+)/(?P<protocolv>[^ ^\"]+))?)|((\"|\s|,)(?P<protocol2>\w+)://(?P<url2>\S+))"
  #strex = ur"((?P<method>GET|POST)\s+((?P<protocol>\w+)://)?(?P<url>\S+)\s+(?P<protocol02>HTTP(S)?)?)|((?P<protocol2>\w+)://(?P<url2>\S+)\s+(?P<protocol2_2>\S+)?)"
  strex=ur"(?P<method>GET|POST)\s+(?P<url>\S+)|((?P<url2>\S+)\s+(?P<protocol2>HTTPS?))|((?P<protocol3>\S+)://(?P<url3>\S+))"
  rex = re.compile(strex)

# go through search elements
  results = splunk.Intersplunk.readResults(None, None, True)
  for res in results:
    logger.debug("---")
    data = res[FIELD]
    logger.debug("DATA: data=\""+data+"\"")
    rexfound = rex.findall(data) # save dict to variable
#     for more help with findall() see https://docs.python.org/2/library/re.html#finding-all-adverbs
#     The dict will look something like:
#     ('POST', 'www.google.ch/test', '', '', '', '', '', '')
#       method, url, , url2, protocol2, , protocol3, url3
#       0       1   2  3     4         5  6          7
    logger.debug("REXFOUND: "+str(rexfound))

    c = 1 # counter for setting numbers at the end of fields
    logger.debug("REXFOUND: Length: "+str(len(rexfound)))
    logger.debug("REXFOUND: "+str(rexfound))

    # code
    if len(rexfound) > 1:
      for i in range(len(rexfound)):
        if rexfound[i][1] != '':
          res[UFPRE+"method_"+str(i+1)] = rexfound[i][0]
          if DECODE:
            res[UFPRE+"url_"+str(i+1)] = urllib.unquote(rexfound[i][1])
          else:
            res[UFPRE+"url_"+str(i+1)] = rexfound[i][1]
        elif rexfound[i][3] != '':
          res[UFPRE+"protocol_"+str(i+1)] = rexfound[i][4]
          if DECODE:
            res[UFPRE+"url_"+str(i+1)] = urllib.unquote(rexfound[i][3])
          else:
            res[UFPRE+"url_"+str(i+1)] = rexfound[i][3]
        elif rexfound[i][7] != '':
          res[UFPRE+"protocol_"+str(i+1)] = rexfound[i][6]
          if DECODE:
            res[UFPRE+"url_"+str(i+1)] = urllib.unquote(rexfound[i][7])
          else:
            res[UFPRE+"url_"+str(i+1)] = rexfound[i][7]
    elif len(rexfound) == 1:
      i=0;
      logger.debug("rexfound single: "+str(rexfound))
      if rexfound[i][1] != '':
        res[UFPRE+"method"] = rexfound[i][0]
        if DECODE:
          res[UFPRE+"url"] = urllib.unquote(rexfound[i][1])
        else:
          res[UFPRE+"url"] = rexfound[i][1]
      elif rexfound[i][3] != '':
        res[UFPRE+"protocol"] = rexfound[i][4]
        if DECODE:
          res[UFPRE+"url"] = urllib.unquote(rexfound[i][3])
        else:
          res[UFPRE+"url"] = rexfound[i][3]
      elif rexfound[i][7] != '':
        res[UFPRE+"protocol"] = rexfound[i][6]
        if DECODE:
          res[UFPRE+"url"] = urllib.unquote(rexfound[i][7])
        else:
          res[UFPRE+"url"] = rexfound[i][7]

      #res[UFPRE+"method"] = rexfound[i][0]
      #res[UFPRE+"url"] = rexfound[i][1]
      #res[UFPRE+"url2"] = rexfound[i][3]
      #res[UFPRE+"protocol2"] = rexfound[i][4]
      #res[UFPRE+"prtocol3"] = rexfound[i][6]
      #res[UFPRE+"url3"] = rexfound[i][7]

    #
    #for i in range(9):
      #if len(rexfound) > 1: # then put a number at the end of the fields
        #pass
#
      #elif len(rexfound) == 1:
        #pass

  
  splunk.Intersplunk.outputResults(results)

if __name__ == "__main__":
  logger.debug("                                                                                ")
  logger.debug("NEW TURN")
  main()
