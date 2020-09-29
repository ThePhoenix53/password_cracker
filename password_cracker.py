from Crypto.Hash import MD5
import itertools
import string

## This is reading in hashes from a file
hash_file = open("hashes.txt", "r")
hashes = hash_file.readlines()
hashes = [hash.strip() for hash in hashes]


def break_password(password_attempt, md5_hash):
    #print(str(len(md5_hash)) + "  -----   " + str(len(MD5.new(password_attempt.encode()).hexdigest())))
    return md5_hash == MD5.new(password_attempt.encode()).hexdigest()

chars = string.printable

# This will brute force a password from 1-4 in length
def brute_forcing():
    attempts = 0
    for password_length in range(1, 5):
        for guess in itertools.product(chars, repeat=password_length):
            attempts += 1
            guess = ''.join(guess)
            target_hash = MD5.new(guess.encode()).hexdigest()
            if target_hash in hashes:
                print("Found March: ", guess, target_hash, "Attempts made: ", str(attempts))

# This uses dictionary to guess passwords
def dictionary_attack(caseSensetive):

    #read in words and put them in a list to iterate over
    dict_file = open("dictionary.txt", "r")
    dictionary = dict_file.readlines()
    dictionary = [dicti.strip() for dicti in dictionary]

    if (caseSensetive):
        dict_upper = [dict_word.upper() for dict_word in dictionary]
        dict_title = [dict_word.title() for dict_word in dictionary]
        dictionary += dict_upper + dict_title

    #guesses passwords
    for guess in dictionary:
        target_hash = MD5.new(guess.encode()).hexdigest()
        if target_hash in hashes:
            print("Match: ", guess, target_hash)

def dictionary_replacement_attack():

    #read in words and put them in a list to iterate over
    dict_file = open("dictionary.txt", "r")
    dictionary = dict_file.readlines()
    dictionary = [dicti.strip() for dicti in dictionary]

    for guess1 in dictionary:
        for guess2 in dictionary:
            guess = guess1 + guess2
            target_hash = MD5.new(guess.encode()).hexdigest()
            if target_hash in hashes:
                print("March: ", guess, target_hash)

def replace_attack():

    #read in words and put them in a list to iterate over
    dict_file = open("dictionary.txt", "r")
    dictionary = dict_file.readlines()
    dictionary = [dicti.strip() for dicti in dictionary]

    for guess in dictionary:
        guess = guess.replace('a', '4')
        guess = guess.replace('A', '4')
        target_hash = MD5.new(guess.encode()).hexdigest()
        if target_hash in hashes:
            print("Match: ", guess, target_hash)

def add_symboles_attack():

    #read in words and put them in a list to iterate over
    dict_file = open("dictionary.txt", "r")
    dictionary = dict_file.readlines()
    dictionary = [dicti.strip() for dicti in dictionary]

    for word in dictionary:
        for symbols in itertools.product("#!$", repeat=2):
            symbols = "".join(symbols)
            guess = word + symbols
            target_hash = MD5.new(guess.encode()).hexdigest()
            if target_hash in hashes:
                print("Match: ", guess, target_hash)




# brute force methode, uncomment when needed
brute_forcing()

# Controls if password guesser is case sensetive in dictiorary attacks
caseSensitive = True;
dictionary_attack(caseSensitive)

dictionary_replacement_attack()

replace_attack()

add_symboles_attack()
