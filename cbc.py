import sys
import re

#######################################################################################################################
###############               Encryption and Decryption in CBC mode Implementation                ######################
############### Created by: Tal Eylon 311117428, Avihoo Menahem 204179832, Amihai Kalev 308469675 #####################
#######################################################################################################################



#######################################################################################################################
############################################ Main CBC class ###########################################################
#######################################################################################################################
### This class handles getting the text, the key and the IV. Then padding, if necessary, is applied and then
### the text will be divided to blocks. Each block is as the same size as the IV.

class CBC():
    """
    Implementation of AES-CBC algorithm. Generic for both encryption and decryption.
    """

    def __init__(self, text_path, key_path, IV_text_path):
        """
        :param text_path: the text we would like to encrypt/decrypt
        :param key_path: the key used for encryption/decryption
        :param IV_text_path: the initialization vector (IV)

        This function processes the text: Load the files according to the paths above,
        then transform the key to a dictionary variable so each letter:letter in key
        will be replaced to key:value.
        Each block size will be as equal as the IV size. Before dividing to blocks,
        required padding will be added (if necessary).
        """

        # filter and avoid any '[' or ']' characters (if necessary)
        text_path = re.sub('[\[\]]', '', text_path)
        key_path = re.sub('[\[\]]', '', key_path)
        IV_text_path = re.sub('[\[\]]', '', IV_text_path)

        self.text_path = text_path # for retrieving file name

        # Load relevant files and avoid any '[' or ']' characters
        with open(IV_text_path, 'r') as file:
            self.IV_text = file.readline()

        with open(text_path,'rb') as file:
            self.text = file.read().decode("UTF-8")

        with open(key_path, 'r') as file:
            self.key_text = file.readlines()

        self.key = self.map_key() # transform key text to a dictionary
        self.padding() # add padding if necessary
        self.blocks = self.divide_to_blocks() # divide text to blocks

    def map_key(self):
        """
        This functions converts the string key to a dictionary. The key in the dictionary will be a-h,
        and the value will be the mapped a-h.
        """
        transformed_key = {}
        for each_exchange in self.key_text:
            the_exchange = each_exchange.split()
            transformed_key[the_exchange[0]] = the_exchange[1]
        return transformed_key

    def padding(self):
        """
        This function adds necessary padding, if the remainder of diving the length of the text
        by the length of the IV is not equal to 0.
        """
        block_remainder = len(self.text) % len(self.IV_text)
        if block_remainder > 0:
            missing_chars = len(self.IV_text) - block_remainder # the number of '\0' we need to add
            self.text += ('\0' * missing_chars)

    def divide_to_blocks(self):
        """
        Divide the loaded text to blocks in the same size as the IV.
        """
        block, blocks = '', []
        for i in range(len(self.text)):
            block += self.text[i]
            if len(block) == len(self.IV_text):
                blocks.append(block)
                block = ''

        return blocks

#######################################################################################################################
########################################### Encryption Class ##########################################################
#######################################################################################################################
### This class applies the encryption. The class inherits the main CBC class above.

class Encryption(CBC):

    def encrypt(self):
        """
        This function applies the encryption. It's acting as follows:
        for each block in text, apply XOR between the previous block and the current block.
        Previous block at the beginning will be the IV.
        Then apply encryption by the key: replace each letter with the one in the key.
        """
        encrypted_text = ''                 # the main encryption string variable.
        previous_block = self.IV_text       # begin with Initialization Vector
        for current_block in self.blocks:   # according to algorithm
            ciphered_block = ''             # the current encrypted block
            for i in range(len(previous_block)):
                # convert the character to the ascii code, then apply xor
                xor = chr(ord(previous_block[i]) ^ ord(current_block[i]))
                # The result exists in the key? replace it with the relevant character from key.
                if xor in self.key:
                    ciphered_block += self.key[xor]
                else: # otherwise just add the result without any further action.
                    ciphered_block += xor

            previous_block = ciphered_block  # update the block to the next iteration
            encrypted_text += ciphered_block # add the encrypted block to the main encrypted text string

        # Write encrypted text to file
        text_name = self.text_path[0:self.text_path.find('.txt')]  # retrieve file name # text.txt
        with open(text_name + '_encrypted.txt', 'wb') as output:    # write in mode='w' #text_encrypted.txt
            output.write(encrypted_text.encode("UTF-8"))

#######################################################################################################################
########################################### Decryption Class ##########################################################
#######################################################################################################################
### This class applies the decryption.
### The class inherit the main CBC class above.

class Decryption(CBC):

    def decrypt(self):
        """
        This function applies the decryption. It's acting as follows:
        for each block in text, at first decrypt the block according to key.
        Then, apply XOR between the previous block and the current block.
        Previous block at the beginning will be the IV.
        """
        decrypted_text = ''                                       # the main decryption string variable.
        reversed_key = {value: k for k,value in self.key.items()} # reverse the key
        previous_block = self.IV_text                             # begin with Initialization Vector
        for current_block in self.blocks:
            deciphered_block = ''                                 # the current decrypted block
            for i in range(len(previous_block)):
                # Apply decryption with the reversed key:
                if current_block[i] in reversed_key:
                    char = reversed_key[current_block[i]]
                else:
                    char = current_block[i]

                # Step 2: apply XOR between the current block and the previous block:
                xor = chr(ord(previous_block[i]) ^ ord(char))
                deciphered_block += xor

            previous_block = current_block     # update the relevant ciphered block to the next iteration
            decrypted_text += deciphered_block # add current deciphered block to the decrypted text

        # Write decrypted text to file
        text_name = self.text_path[0:self.text_path.find('.txt')]  # retrieve file name
        with open(text_name + '_decrypted.txt', 'wb') as output:    # write in mode='w'
            output.write(decrypted_text.encode("UTF-8"))


#######################################################################################################################
############################################## MAIN PROGRAM ###########################################################
#######################################################################################################################
##### For usage in command prompt
if sys.argv[1] == "Encryption":
    text = Encryption(sys.argv[2],sys.argv[3],sys.argv[4])
    text.encrypt()
elif sys.argv[1] == "Decryption":
    text = Decryption(sys.argv[2], sys.argv[3], sys.argv[4])
    text.decrypt()