# -*- coding: utf-8 -*-

import hashlib
from fields import PasswordField

class PasswordHandler:
    """
        Check encrypted password 
        
            Example:
            
                bpass = PasswordHandler()
                is_valid = bpass.verify("sha1$e7eHHdB$7033e721c7a9ed84f7d473d99da92b00a7ca81f","sha1$e7eHHdB$7033e721c7a9ed84f7d473d99da92b00a7ca81fb")
                --> return is_valid=False
                
    """
    
    def hexdigest(self,password):
        if self.algorithm == PasswordField.ALGORITHM_CRYPT:
            try:
                import crypt
            except ImportError:
                self.error("crypt module not found in this system. Please use md5 or sha* algorithm")
            return crypt.crypt(password, self.salt)
        
        try:
            import hashlib
        except ImportError:
            self.error("hashlib module not found in this system.")
        
        ''' use sha1 algoritm '''
        if self.algorithm == PasswordField.ALGORITHM_SHA1:
            return hashlib.sha1(self.salt + password).hexdigest()
        elif self.algorithm == PasswordField.ALGORITHM_MD5:
            return hashlib.md5(self.salt + password).hexdigest()
        elif self.algorithm == PasswordField.ALGORITHM_SHA256:
            return hashlib.sha256(self.salt + password).hexdigest()
        elif self.algorithm == PasswordField.ALGORITHM_SHA512:
            return hashlib.sha512(self.salt + password).hexdigest()
        raise ValueError('Unsupported hash type %s' % self.algorithm)        
    
    def encode(self, password):
        """
            Creates an encoded password

            The result is normally formatted as "algorithm$salt$hash"
            
        """
        password =  self.hexdigest(password)
        return '%s$%s$%s' % (self.algorithm,self.salt,password)
    
    def decode(self,encoded_password):
        """
            Decode password

            The result is normally formatted as "algorithm$salt$hash" like in the example:
            ha1$SgwcbaH$20f16a1fa9af6fa40d59f78fd2c247f426950e46
        
        """        
        (self.algorithm,self.salt,self.hash) = encoded_password.split(PasswordField.DOLLAR)
        if self.algorithm is None:
            raise Exception("Algorithm not found in encrypted password")
        if self.salt is None:
            raise Exception("Password salt not found in encrypted password")
    
    def verify(self, password, encoded_password):        
        """
            Checks if the given password is correct
        """
        self.decode(encoded_password)
        input_encoded_password = self.encode(password)
        return self._compare(encoded_password, input_encoded_password)

    def _compare(self,value1,value2):
        """
            Returns True if the two strings are equal, False otherwise.
        """
        if len(value1) != len(value2):
            return False
        result = 0
        for x, y in zip(value1, value2):
            result |= ord(x) ^ ord(y)
        return result == 0
