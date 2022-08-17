import pandas as pd
import pandas.errors
from sql_utils.sqlQuery import SqlQuery
from crypto.crypto import Crypto
from datetime import datetime
import rsa


class User:
    def __init__(self, user: list, key):
        self.user_id = user[0]
        self.user_name = user[1]
        self.public_key = rsa.PublicKey.load_pkcs1(user[4])
        self.private_key = rsa.PrivateKey.load_pkcs1(key)
        self.crypto = Crypto()
        try:
            self.outbox = pd.read_csv(f".info\{self.user_name}\outbox\messages.csv")
        except FileNotFoundError:
            open(f".info\{self.user_name}\outbox\messages.csv","wb").close()
            self.outbox = pd.DataFrame(columns=["id","receiver","title","message","date","attachment"])
        except pandas.errors.EmptyDataError:
            self.outbox = pd.DataFrame(columns=["id","receiver","title","message","date","attachment"])

    def get_inbox(self):
        return SqlQuery.select_inbox(self.user_id)

    def send_message(self,title:str ,message: bytes, user_name,method="s", attachment=None):
        """
        :param message: Text of content
        :param method: It can be "s"(sign),"e"(encrypt),"se"(sign and encrypt)
        :param attachment: If there is NOT an attachment(video,image,file) in the message leave it as None
        :return: For s : encryted_message_hash ,
                For e : encrypted_message, encrypted_aes ,
                For se or es : encrypted_message_hash, encrypted_message, encrypted_aes added to Database
        """
        if attachment:
            with open(attachment,"rb") as file:
                attachment_content = file.read()
            ext = "."+attachment.split(".")[-1]

        result = []
        receiver = SqlQuery.select_user_by_name(user_name)
        rec_public = rsa.PublicKey.load_pkcs1(receiver[4])
        result.append(self.user_id)
        result.append(receiver[0])
        result.append(title)
        date_str = str(datetime.now())
        if method == "s":
            result.append(1)
            result.append(message)
            result.append(rsa.sign(message,self.private_key,"SHA-256"))
            if attachment:
                result.append(attachment_content)
                result.append(rsa.sign(attachment_content,self.private_key,"SHA-256"))
                result.append(ext)
            result.append(date_str)
            SqlQuery.insert_signed_message(result)
        elif method == "e":
            result.append(2)
            encrypted_message, encrypted_aes,aes_key = self.crypto.encrypt(message, rec_public)
            result.append(encrypted_message)
            result.append(encrypted_aes)
            if attachment:
                encrypted_attachment,_,_ = self.crypto.encrypt(attachment_content,rec_public,aes_key)
                result.append(encrypted_attachment)
                result.append(ext)
            result.append(date_str)
            SqlQuery.insert_encrypted_message(result)
        elif method == "se" or method == "es":
            result.append(3)
            result.append(rsa.sign(message,self.private_key,"SHA-256"))
            encrypted_message, encrypted_aes,aes_key = self.crypto.encrypt(message, rec_public)
            result.append(encrypted_message)
            result.append(encrypted_aes)
            if attachment:
                result.append(rsa.sign(attachment_content,self.private_key,"SHA-256"))
                encrypted_attachment, _, _ = self.crypto.encrypt(attachment_content, rec_public, aes_key)
                result.append(encrypted_attachment)
                result.append(ext)
            result.append(date_str)
            SqlQuery.insert_signed_encrypted(result)
        else:
            raise Exception(f"Method must be 's'(sign),'e'(encrypt),'se'(sign and encrypt) not {method}")

        message_id = SqlQuery.select_message_id(self.user_id)
        if not message_id:
            message_id = 1
        message_dict = {"id":message_id,"receiver":user_name,"title":title,"message":message.decode("utf-8"),
                        "date":date_str,"attachment":"-"}
        if attachment:
            with open(f".info\{self.user_name}\outbox\{message_id}{ext}","wb") as attfile:
                attfile.write(attachment_content)
            message_dict["attachment"] = f"{message_id}{ext}"
        self.outbox = self.outbox.append(message_dict,ignore_index=True)
        self.outbox.to_csv(f".info\{self.user_name}\outbox\messages.csv",index=False)


    def get_message(self, message):
        sender_public = rsa.PublicKey.load_pkcs1(SqlQuery.select_public_key(message[1])[0])
        if message[4]==1: #Verify
            try:
                rsa.verify(message[5],message[6],sender_public)
                if message[12]:
                    rsa.verify(message[9],message[10],sender_public)
                    path = f".info\{self.user_name}\inbox\{message[0]}{message[12]}"
                    with open(path, "wb") as file:
                        file.write(message[9])
                    return True,path
                return True,False
            except rsa.pkcs1.VerificationError:
                return False
        elif message[4]==2: #Decrypt
            plain_text = self.crypto.decrypt(message[7], message[8], self.private_key)
            if message[12]:
                plain_file = self.crypto.decrypt(message[11],message[8],self.private_key)
                path = f".info\{self.user_name}\inbox\{message[0]}{message[12]}"
                with open(path,"wb") as file:
                    file.write(plain_file)
                return plain_text,path
            return plain_text,""
        else: # Verify and Decrypt
            plain_text = self.crypto.decrypt(message[7], message[8], self.private_key)
            if message[12]:
                plain_file = self.crypto.decrypt(message[11], message[8], self.private_key)
            try:
                rsa.verify(plain_text,message[6],sender_public)
                if message[12]:
                    rsa.verify(plain_file,message[10],sender_public)
                    path = f".info\{self.user_name}\inbox\{message[0]}{message[12]}"
                    with open(path, "wb") as file:
                        file.write(plain_file)
                    return plain_text,path
                return plain_text,""
            except rsa.pkcs1.VerificationError:
                return False,False