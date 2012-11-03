#*****************************************************************************
# Copyright 2012 John Steven - m1spl4c3ds0ul@gmail.com
#
# Licensed under the Eclipse License, Version 1.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.eclipse.org/legal/epl-v10.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *** DEPENDENCIES ***
#  This utility requires a specific PBKDF2 implementation. 
#  See: http://pypi.python.org/pypi/pbkdf2 
#
# This utility does two primary functions. First, it takes a password file 
# generates a pw digest file. The digest algorithm is hard-coded and takes
# the form: 
#
#   salt:32B || digest:160B = PBKDF2(HMAC-SHA-1, salt, pw, c=1)
#    salt = UUID4() - unique to each password
# 
# The second purpose of this utility is to take a plain-text password and
# attempt to find its salted digest within the digest file. Comparison 
# based (optionally) on a specified chunk size. 
#
# Usage 1 - Salted digest generation: 
# q_split_hash_test 
#         -p | --password_file= <input password file> 
#         -h | --hash_file= <output digest file>
#         [-n | --max_count= <total number of digest to generate]
#
# Usage 2 - Password search in salted digest file
# q_split_hash_test
#         -h | --hash_file= <output digest file> 
#         -v | --verify= <password to verify> 
#         [-c | --chunk_size= <chunk size in bytes>] 
#         [-n | --max_count= <total number of digests to check]
#
# Regardless of which usage the user choses, this utility will print out
# progress at a specified hardcoded interval (10,000 iterations). 
# 
# Author: John Steven - m1spl4c3ds0ul@gmail.com
# Created: 2012-10-18
# Last Changed By: $Author
# Modified: $LastChangedDate
#***************************************************************************/

## Imports important for digesting operations
from pbkdf2 import PBKDF2 #See: http://pypi.python.org/pypi/pbkdf2
import uuid
from hashlib import sha1

## Boring ancillary imports
import operator

## Imports for shell interaction, timing, and progress reporting
import getopt
import sys
from datetime import datetime

# Interval at which progress is printed
INTERVAL = 10000
# Size, in bytes, of the randomly (SPRNG) generated salt
SALT_SIZE = 8
# Output size, in bytes (160b) 
HASH_OUTPUT_BLOCK_SIZE = 20

def createHashes(fp_passwords, fp_hashes, max_count):
  """ 
    function createHashes(fp_passwords, fp_hashes, max_count)
       * fp_passwords - (input) path to file containing password list
       * fp_hashes - (output) path to file salted digests are to be written
       * max_count - (input, OPTIONAL) - number of digests to generate

      ASSUMPTIONS:
       * Passwords w/in file are stored one (1) per line
       * max_count <= number of passwords in file.
       * Password file comments are lines starting w/ " " or "#"
       * User desires rate reporting only if count >= INTERVAL

       This function iterates through a file of passwords, expecting one
       per line, and computes a uniquely salted digest, storing it in the 
       specified "hashes" file. The scheme used is:

       salt:32B || digest:160B = PBKDF2(HMAC-SHA-1, password, salt:32B, c=1)

      In this case, passwords are 'unbounded' but most be a single
      line read from the input file.

      The output file file of digests is sorted in increasing order (by 
      numerical value) in order to make manual visual inspection easier. 
    
      SIDE EFFECTS:
      * Prints digest check throughput at INTERVAL
  """
  num_pws = 0
  hashes = list()
  
  start_t = datetime.now()
  for line in fp_passwords:
    if ((line[0] == '#') or (line[0] == ' ')): continue
    pw = line.strip()
    salt = ''.join(['%02X' %ord(x) for x in uuid.uuid4().bytes[0:SALT_SIZE]])
    pw_hash = PBKDF2(pw,salt).hexread(HASH_OUTPUT_BLOCK_SIZE)
    protected_pw = ''.join([salt, pw_hash])
    hashes.append(protected_pw)
    num_pws = num_pws + 1
    if num_pws % INTERVAL == 0:
	    end_t = datetime.now()    
	    print '%d (total) hashes computed @%d/sec' %(num_pws, INTERVAL/(end_t-start_t).seconds)
	    start_t = end_t
    if num_pws == max_count:
      break
  
  hashes.sort()
  return hashes

def checkHash(fp, pw, chunk_size=HASH_OUTPUT_BLOCK_SIZE, max_count=sys.maxint):
  """
    checkHash(fp, pw, chunk_size=HASH_OUTPUT_BLOCK_SIZE, max_count=sys.maxint)

      * fp - (input) filepointer to file of salted digests to check.
      * pw - (input) Password against which salted digests are checked.
      * chunk_size - (input,OPTIONAL) size, in octets of the digest to compare
                      chunk_size computed from "rear" (least significant bits)
                      of the digest. Salt is never considered as digest salt
                      is always used.
      * max_count - (input,OPTIONAL) maximum number of digests to consider.

      ASSUMPTIONS:
      * max_count <= number of passwords in file.
      * User desires rate reporting only if count >= INTERVAL
      * chunk_size smaller than digest size

      Comparison done through masking and xor comparison. This approach, through
      perhaps less intuitive than alternatives has advantages. It performs 
      nominally-faster or roughly equivalent to array splitting in speed. 

      Calling this utility two or three times in parallel appears to achieve 
      optimal throughput results, depending on machine-specific factors.    

      RETURNS:
      * A list of matching salted digests (aka, digests computed from the 
        given password)

      SIDE EFFECTS: 
      * Prints "Found match..." when a match is Found
      * Prints digest check throughput at INTERVAL  
  """
  matches = list()
  num_pws = 0

  salt_len = SALT_SIZE * 2
  end_block = HASH_OUTPUT_BLOCK_SIZE * 2
  start_block = end_block - chunk_size
  start_after_salt = salt_len + start_block

  #### Set up test mask
  test_mask = list()
  for i in range(0, start_block + salt_len): test_mask.append('0')
  for i in range(start_block, end_block): test_mask.append('F')
  test_mask=int(''.join(test_mask), 16)  

  start_t = datetime.now()
  for line in fp:
    salted_hash = line.strip()
    if (line[0] == '#'):
      continue
    
    num_pws = num_pws + 1
    if num_pws >= max_count:
      break
    
    salt = salted_hash[0:salt_len]
    test_hash = PBKDF2(pw, salt).hexread(HASH_OUTPUT_BLOCK_SIZE)
    if operator.xor(test_mask & int(test_hash,16), test_mask & int(salted_hash,16)) == 0:
     matches.append(salted_hash)
     print "Found match in %s w/ %s" %(salted_hash, test_hash)

    if num_pws % INTERVAL == 0:
      end_t = datetime.now()    
      print '%d (total) hashes computed @%d/sec' %(num_pws, INTERVAL/(end_t-start_t).seconds)
      start_t = end_t
  return matches

if __name__ == "__main__":
  
  pw_file_name = False
  hash_file_name = False
  max_count = sys.maxint
  password_to_verify = None
  chunk_size = HASH_OUTPUT_BLOCK_SIZE * 2
  try:
	opts, args = getopt.getopt(sys.argv[1:],
	                           "p:h:n:v:c:",
	                           ["password_file=", "max_count=", "hash_file=", 
                              "verify=", "chunk_size="])
  except getopt.error, msg:
    print msg
    print "-h | --hash_file= <path to hash file>"
    print " ------"
    print "For hash file creation:"
    print "  -p | --password_file= <path to password file>"
    print "  (OPTIONAL) -n | --max_count= <total number of hashes to generate>"
    print " ------"
    print "For hash verification:"
    print "  -v | --verify= <password to verify>"
    print "  -c | --chunk_size= <amount of PW (from low-order bits) to verify>"
    print "  -n | --max_count= <total number of PWs to attempt verification on>"

    
    sys.exit(1)
  
  for o, a in opts:
    if o in ('-p', '--password_file'):
      pw_file_name = True
      pw_file_path = a
    if o in ('-h', '--hash_file'):
      hash_file_name = True
      hash_file_path = a
    if o in ('-n', '--max_count'):
      max_count = int(a)
      print "Will stop @ %d hashes" %(max_count)
    if o in ('-v', '--verify'):
      password_to_verify = a
    if o in ('-c', 'chunk_size'):
      requested_chunk = int(a)
      if requested_chunk > chunk_size:
        print "Chunk size can not be larger than %s" %(chunk_size)
        sys.exit(-1) 
      print "+ Chunk size = %d" %(requested_chunk)
      chunk_size = requested_chunk
  if (password_to_verify != None):
    fr = open(hash_file_path, 'r')

    if (pw_file_name):
      print "Do not specify password file for hash verification"
      sys.exit(1)

    matching = checkHash(fr, password_to_verify, chunk_size, max_count)
    print "+ Found %s verifying passwords" %(matching)
    print "+ %d total matching" %(len(matching))
    sys.exit(0)
  
  if not (pw_file_name and hash_file_name):
    print "Must specify pw and hash file path."
    print "-p | --password_file= <path to password file>"
    print "-h | --hash_file= <path to hash file>"
    sys.exit(1)
  
  fr = open(pw_file_path, 'r')
  fw = open(hash_file_path, 'w')
  
  hashes = createHashes(fr, fw, max_count)
  fr.close()
  
  num_hashes = 0
  for h in hashes:
	fw.write(h +'\n')
	num_hashes = num_hashes + 1
	if num_hashes % INTERVAL*100 == 0:
		print "+ Wrote %d hashes" %(num_hashes)
  
  fw.close()
  sys.exit(0)
