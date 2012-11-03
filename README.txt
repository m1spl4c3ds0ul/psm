PSM - Secure Password Storage Module
========
This project describes goals, threats, and design for a 
reusable password storage module (PSM or module). Contents
include:

* Presentation Material - As presented @OWASP AppSecUSA Austin 2012
* Documents - Threat Model and Attacker vs. Defender Spreadsheet
* Demo code - Split hash collision utility (Python 2.x)
========

[Presentation Material]
* Secure Password Storage AUS (w/ Notes).pptx.pdf - With notes
* Secure Password Storage AUS.pptx.pdf - Full-size slides, no notes

[Documents]
* ThreatModelforPWStorage.pdf - PDF print of PW Storage Threat Model
                                Google doc @ http://goo.gl/Spvzs
* Password Scheme Attacker Defender Cost Comparison Sheet.xlsx 

[code]
* split_hash_util.py - Python utility for generating uniquely salted
       PBKDF2 hashes and then brute forcing them in full or in chunks

This material is not a finished Password Storage Module but simply a 
"As-is" dump of material as presented at OWASP AppSecUSA Austin 2012.

Please contact with questions/comments:
John Steven - john.steven@owasp.org - @M1splacedsoul
