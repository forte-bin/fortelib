#!/usr/bin/env python
import string
import re
from Crypto.Cipher import AES
from collections import defaultdict
import bruteforce
import os

CHAR_FREQ = {"a":8.55, "k":0.81, "u":2.68, "b":1.60, "l":4.21, "v":1.06, "c":3.16, "m":2.53, "w":1.83, "d":3.87, "n":7.17, "x":0.19, "e":12.10, 
			 "o":7.47, "y":1.72, "f":2.18, "p":2.07, "z":0.11, "g":2.09, "q":0.10, "h":4.96, "r":6.33, "i":7.33, "s":6.73, "j":0.22, "t":8.94,  " ":8.00}#space is a guess			   
EXTRA_CHARS = "\x00"
FLAG_FORMAT = re.compile('[a-zA-Z]{4}\\{[a-zA-Z0-9_-]{1,32}\\}')
def xor_str(s1, s2):
	return ''.join(chr(ord(s[0]) ^ ord(s[1])) for s in zip(s1, s2))

def flaglike(s):
	match = FLAG_FORMAT.match(s)
	if match:
		return match.group(0)
	return None

def englishness(s):
	if s is None:
		return 0
	from scipy.stats import chisqprob
	#uses a chi square algorithm to match the relative charcter frequencies
	#in the test string to that of real english
	score = 0
	s = s.lower()
	for c in EXTRA_CHARS:
		s = s.replace(c,'')#completely ignore characters in EXTRA_CHAR
	frequency = defaultdict(float)
	ignored = 0 #ignore, but only for purpose of chisquare computation
	length = len(s)
	for i in s:
		#analyze each character
		if i not in string.printable: #non-printables are bad
			score += 2
			ignored += 1
		elif i in string.digits: #digits arent that bad
			score += 0.5
			ignored += 1
		elif i not in string.ascii_lowercase and i not in ' ':#special chars are eh
			score += 1
			ignored += 1
		else:
			frequency[i] += 1 #analyze alphabetic frequencies.
		
	for i in frequency:
		freq = frequency[i] / (length - ignored)
		# Chi square
		score += pow((freq - CHAR_FREQ[i]/100), 2) / (CHAR_FREQ[i]/100)
	if not score:
		return 0
	return chisqprob(score,1) * 100 #return probability

def caesar_shift(s,k):
	translation = string.ascii_lowercase[k:] + string.ascii_lowercase[:k]
	translation += string.ascii_uppercase[k:] + string.ascii_uppercase[:k]
	translation = string.maketrans(string.ascii_lowercase + string.ascii_uppercase, translation)
	return string.translate(s,translation)

def single_byte_xor_search(s, returnKey=False):
	return max_englishness_search(xrange(256), s, lambda s,k:''.join(chr(ord(c) ^ k) for c in s), returnKey)
	

def caesar_search(s,returnKey=False):
	return max_englishness_search(xrange(26),s,caesar_shift,returnKey)

def max_englishness_search(keygen,ciphertext='',process=lambda x,y:y,returnKey=False):
	maxScore = 0
	result = None
	for k in keygen:
		score = englishness(process(ciphertext,k))
		if maxScore < score:
			maxScore = score
			result = k
	if returnKey:
		return result
	else:
		return process(ciphertext,result)

def repeated_key_xor(s,k):
	#k and s are strings, can be differing lengths
	result = ''
	for i in range(max(len(k),len(s))):
		result += chr(ord(s[i%len(s)]) ^ ord(k[i%len(k)]))
	return result

def hamming_distance(s1,s2):
	if not isinstance(s1,basestring) or not isinstance(s2,basestring):
		raise TypeError('s1 and s2 must be strings')
	if len(s1) != len(s2):
		raise ValueError('s1 and s2 must be the same length')
	error = 0
	for i, j in zip(s1,s2):
		error += count_set_bits(ord(i)^ord(j))
	return error
	
def hamming_char_distance(s1,s2):
	if not isinstance(s1,basestring) or not isinstance(s2,basestring):
		raise TypeError('s1 and s2 must be strings')
	if len(s1) != len(s2):
		raise ValueError('s1 and s2 must be the same length')
	error = 0
	for i, j in zip(s1,s2):
		if i != j:
			error += 1
	return error

def count_set_bits(testByte):
	#counts set bits in tests byte.
	#masks out only the low byte
	testByte = testByte & 0b11111111
	count = 0
	check = 0b1
	for i in range(8):
		if testByte & check:
			count += 1
		check *= 2
	return count

def guess_key_length(s, minKeyLen, maxKeyLen):
	#uses hamming distance to guess key length of an encrypted ciphertext
	#s is ciphertext
	if maxKeyLen > len(s):
		raise ValueError('max key length must be less than or equal to length of ciphertext')
	if minKeyLen > maxKeyLen:
		raise ValueErrot('max key length must be larger than min key length')
	scores = {}
	for i in range(minKeyLen,maxKeyLen+1):
		length = len(s) - (len(s)%i)
		l = [ s[j:j+i] for j in range(0, length, i) ]
		permutations = 0
		distance = 0
		for a in range(len(l)-1):
			for b in range(a+1,len(l)):
				permutations += 1
				distance += hamming_distance(l[a],l[b])
		scores[i] = distance/float(permutations)/float(i)
	v = list(scores.values())
	k = list(scores.keys())
	return k[v.index(min(v))]
	
def transpose_string(s,columns):
	l = [''] * columns
	for i in range(len(s)):
		l[i%columns] += s[i]
	return l

def guess_repeated_key(s,min=2,max=-1,guessFunction = single_byte_xor_search):
	#guesses key of string which has been encrypted with a repeated key
	#guessFinction must be of form guessFunction(inputString,returnsKey)
	#see single_byte_xor_search or caezer_search for examples
	if max == -1:
		max = len(s)
	if max < min:
		raise ValueError('max length must be larger than min length')
	keysize = guess_key_length(s,min,max)
	l = transpose_string(s,keysize)
	key = ''
	for i in l:
		key += chr(guessFunction(i,True))
	return key

def encrypt_ecb(plaintext,key):
	cipher = AES.new(key,AES.MODE_ECB)
	return cipher.encrypt(pad(plaintext,16))

def decrypt_ecb(ciphertext,key):
	cipher = AES.new(key,AES.MODE_ECB)
	return cipher.decrypt(ciphertext)

def encrypt_cbc(plaintext, key, iv):
	ciphertext = ''
	blocks = chunkstring(pad(plaintext,16),16)
	for i in blocks:
		cblock = encrypt_ecb(xor_str(iv,i),key)
		iv = cblock
		ciphertext += cblock
	return ciphertext

def decrypt_cbc(ciphertext, key, iv):
	if len(ciphertext) % 16 != 0:
		raise ValueError('invalid ciphertext')
	plaintext = ''
	blocks = chunkstring(ciphertext,16)
	for i in blocks:
		pblock = xor_str(decrypt_ecb(i,key),iv)
		iv = i
		plaintext += pblock
	return plaintext

def encryption_oracle(plaintext):
	#append and prepend 5-10 random characters
	plaintext = os.urandom(ord(os.urandom(1))%6+5) + plaintext + os.urandom(ord(os.urandom(1))%6+5)
	
	key = os.urandom(16)
	if ord(os.urandom(1)[0]) % 2 == 0:
		print 'ecb'
		return encrypt_ecb(plaintext,key)
	else:
		print 'cbc'
		iv =os.urandom(16)
		print encrypt_cbc(plaintext,key,iv)
		return encrypt_cbc(plaintext,key,iv)

def is_ECB_Blackbox(function):
	plaintext = 'A'*54 #16*2 +(16-5)*2
	ciphertext = function(plaintext)
	#print ciphertext
	return detect_ecb(16,ciphertext)

def chunkstring(text, length):
	return [text[i:length+i] for i in range(0, len(text), length)]


def detect_ecb(blocksize,s):
	#s is ciphertext
	#just checks if any blocks are equivalent
	l = []
	while len(s) >= blocksize:
		q = s[:blocksize]
		s = s[blocksize:]
		if q in l:
			print q
			return True
		l.append(q)
	return False

def pad(message, blocksize):
	#placeholder padding function, uses pkcs#7 by defualt
	return _pkcs7(message, blocksize)
	
def _pkcs7(message, blocksize):
	#implements pkcs#7 padding
	if type(blocksize) != int:
		raise TypeError('blocksize must be an int')
	if blocksize > 0xff:
		raise ValueError('blocksize must be less than or equal to 0xff')
	padding = blocksize - (len(message) % blocksize) 
	if padding == 0:
		return message
	return message + chr(padding) * padding