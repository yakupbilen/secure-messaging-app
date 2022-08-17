from sql_utils.connection import connection,cursor


class SqlQuery:
    @staticmethod
    def select_user_by_name(user_name: str):
        query = "SELECT * FROM users WHERE user_name=?"
        cursor.execute(query, (user_name,))
        return cursor.fetchone()

    @staticmethod
    def insert_user(user: list):
        query = "INSERT INTO users(user_name,salt,password,public_key) VALUES (?,?,?,?)"
        cursor.execute(query, user)
        connection.commit()

    @staticmethod
    def select_users():
        query = "SELECT * FROM users"
        cursor.execute(query)
        return cursor.fetchall()

    @staticmethod
    def select_user_by_id(user_id: int):
        query = "SELECT * FROM users WHERE id=?"
        cursor.execute(query, (user_id,))
        return cursor.fetchone()

    @staticmethod
    def select_signed_message(message_id: int):
        query = "SELECT * FROM  messages WHERE id = ?"
        cursor.execute(query, (message_id,))
        return cursor.fetchone()

    @staticmethod
    def insert_signed_message(message: list):
        if len(message)==10:
            query = "INSERT INTO messages(sender,receiver,title,type,message,message_hash,attachment,attachment_hash,file_ext,date) VALUES (?,?,?,?,?,?,?,?,?,?)"
        else:
            query = "INSERT INTO messages(sender,receiver,title,type,message,message_hash,date) VALUES (?,?,?,?,?,?,?)"

        cursor.execute(query, message)
        connection.commit()

    @staticmethod
    def insert_encrypted_message(message: list):
        if len(message)==9:
            query = "INSERT INTO messages(sender,receiver,title,type,enc_message,enc_aes,enc_attachment,file_ext,date) VALUES(?,?,?,?,?,?,?,?,?)"
        else:
            query = "INSERT INTO messages(sender,receiver,title,type,enc_message,enc_aes,date) VALUES(?,?,?,?,?,?,?)"
        cursor.execute(query, message)
        connection.commit()

    @staticmethod
    def insert_signed_encrypted(message: list):
        if len(message)==11:
            query = "INSERT INTO messages(sender,receiver,title,type,message_hash,enc_message,enc_aes,attachment_hash,enc_attachment,file_ext,date)" \
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)"
        else:
            query = "INSERT INTO messages(sender,receiver,title,type,message_hash,enc_message,enc_aes,date)" \
                    "VALUES (?,?,?,?,?,?,?,?)"
        cursor.execute(query, message)
        connection.commit()

    @staticmethod
    def select_public_key(user_id: int):
        query = "SELECT public_key FROM users WHERE id=?"
        cursor.execute(query, (user_id,))
        return cursor.fetchone()

    @staticmethod
    def select_inbox(user_id: int):
        query = "SELECT * FROM messages WHERE receiver=?"
        cursor.execute(query, (user_id,))
        return cursor.fetchall()

    @staticmethod
    def select_message_id(user_id:int):
        query = "SELECT max(id) FROM messages WHERE sender=?"
        cursor.execute(query,(user_id,))
        return cursor.fetchone()[0]
