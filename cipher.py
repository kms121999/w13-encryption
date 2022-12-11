##############################################################################
# COMPONENT:
#    CIPHER01
# Author:
#    Br. Helfrich, Kyle Mueller, Keaton Smith
# Summary:
#    Implement your cipher here. You can view 'example.py' to see the
#    completed Caesar Cipher example.
##############################################################################


##############################################################################
# CIPHER
##############################################################################
class Cipher:
    def __init__(self):
        # Nothing needed here for the Columnar Transposition
        pass

    def get_author(self):
        return "Keaton Smith"

    def get_cipher_name(self):
        return "Columnar Transposition"

    ##########################################################################
    # GET CIPHER CITATION
    # Returns the citation from which we learned about the cipher
    ##########################################################################
    def get_cipher_citation(self):
        return "Christensen, Chris. \"Columnar Transposition.\" Spring 2015\n" \
               "\thttps://www.nku.edu/~christensen/1402%20Columnar%20transposition.pdf\n" \
               "\n" \
               "Kowalczyk, Chris. \"Columnar Transposition.\" 9 Mar. 2020\n" \
               "\thttp://www.crypto-it.net/eng/simple/columnar-transposition.html"

    ##########################################################################
    # GET PSEUDOCODE
    # Returns the pseudocode as a string to be used by the caller
    ##########################################################################
    def get_pseudocode(self):

        # The encrypt pseudocode
        pc = "encrypt(plainText, password)\n" \
             "   keyLength <- LENGTH of password\n" \
             "   grid <- array of length keyLength populated with empty strings\n" \
             "   iColumn <- 0\n" \
             "   FOR each char in plainText\n" \
             "      grid[iColumn] <- grid[iColumn] + char\n" \
             "      iColumn <- (iColumn  + 1) % keyLength\n" \
             "   readOrder <- getGridReadOrder(password)\n" \
             "   cipherText <- empty string\n" \
             "   FOR each columnIndex in readOrder\n" \
             "      cipherText += grid[columnIndex]\n" \
             "   RETURN cipherText\n\n"

        # The decrypt pseudocode
        pc += "decrypt(cipherText, password)\n" \
              "   minColumnLength <- FLOOR ( (LENGTH of cipherText) / (LENGTH of password) )\n" \
              "   pivotOfShortColumns <- (LENGTH of cipherText) MOD (LENGTH of password)\n" \
              "   gridReadOrder <- getGridReadOrder(password)\n" \
              "   grid <- array of length (LENGTH of password) populated with empty strings \n" \
              "   readIndex <- 0\n" \
              "   FOR each iColumn in readOrder\n" \
              "      readLength <- minColumnLength\n" \
              "      IF iColumn < pivotOfShortColumns\n" \
              "         readLength += 1\n" \
              "      grid[iColumn] <- cipherText[readIndex UPTO (readIndex + readLength)]\n" \
              "      readIndex += readLength\n" \
              "   plainText <- empty string\n" \
              "   FOR iRow FROM 0 UPTO (minColumnLength + 1)\n" \
              "      FOR iColumn FROM 0 UPTO (LENGTH of grid)\n" \
              "         IF iRow == minColumnLength AND iColumn >= pivotOfShortColumns\n" \
              "            BREAK\n" \
              "         plainText += grid[iColumn][iRow]\n" \
              "   RETURN plainText\n\n"

        # Helper function to get order of grid read
        pc += "getGridReadOrder(password)\n" \
              "   readOrder <- SORT(password)\n" \
              "   gridReadOrder <- []\n" \
              "   FOR each char in readOrder\n" \
              "      FOR i FROM 0 UPTO LENGTH of password\n" \
              "         IF char EQUALS password[i] AND i NOT IN gridReadOrder\n" \
              "            APPEND i to gridReadOrder\n" \
              "            BREAK\n" \
              "   RETURN gridReadOrder\n"

        return pc

    ##########################################################################
    # ENCRYPT
    # Generate a grid of width len(password) and then concatenate columns in
    # ascending ASCII-value order
    ##########################################################################
    def encrypt(self, plaintext, password):
        key_len = len(password)

        # Initialize the grid with empty strings
        # Assures that len(grid) == len(password)
        grid = [""]  * key_len

        # Populate the grid
        # Inserts plaintext one character at a time
        # Starts at left column and loops as necessary
        i_col = 0
        for char in plaintext:
            grid[i_col] += char
            i_col = (i_col + 1) % key_len
        
        # Get the order of the ciphertext translation
        read_order = self._get_grid_read_order(password)

        # Generate the ciphertext
        ciphertext = ""
        for i in read_order:
            ciphertext += grid[i]
            
        return ciphertext

    ##########################################################################
    # DECRYPT
    # Read ciphertext into a grid based on the ASCII-order of the password
    # and then read grid from left-to-right then top-to-bottom to generate
    # decrypted text
    ##########################################################################
    def decrypt(self, ciphertext, password):
        # Used to determine the length of a given column
        min_col_length = (len(ciphertext) // len(password))
        i_pivot_short_cols = len(ciphertext) % len(password)

        # Get the order of the ciphertext columns
        read_order = self._get_grid_read_order(password)

        # Assure that len(grid) == len(password)
        grid = [""] * len(password)

        # Generate the original grid made with the plaintext
        i_read = 0
        for i_col in read_order:
            # Determine the length of the column to be read
            read_len = min_col_length + (1 if i_col < i_pivot_short_cols else 0)
            # Read the column
            grid[i_col] = ciphertext[i_read:(i_read + read_len)]
            # Shift index to next column
            i_read += read_len
        
        # Extract plaintext from grid
        plaintext = ""
        for i_row in range(min_col_length + 1):
            for i_col in range(len(grid)):
                # Check if we've reached the end of the grid
                if i_row == min_col_length and i_col >= i_pivot_short_cols:
                    break
                # Else...
                plaintext += grid[i_col][i_row]

        return plaintext

    #######################################################
    # GET GRID READ ORDER
    # Return an array holding the indices of password's
    # characters in ASCII-sorted order
    #######################################################
    def _get_grid_read_order(self, password):
        read_order = []
        
        # Get the ASCII-sorted indexs of the chars in password
        for char in sorted(password):
            for i in range(len(password)):
                if char == password[i] and i not in read_order:
                    read_order.append(i)
                    break
        
        return read_order