"""
Program developed and tested on Windows.
messages table:
index,name
0,id
1,sender_id
2,receiver_id
3,title
4,type(1(signed),2(encrypted),3(signed and encrypted))
5,plain_message
6,message_hash
7,encrypted_message
8,encrypted_aes_key
9,plain_attachment
10,attachment_hash
11,encrypted_attachment
12,attachment_extension(.mp4,.png,.txt)
13,date


users tablosu:
1,id
2,user_name
3,hashed_salt
4,hashed(hashed_salt+hashed_password)
5,public_key
!Private keys store in user-client computers..
"""
from PyQt5.QtWidgets import QApplication
import sys
from widgets.login import Ui_Login


app = QApplication(sys.argv)
window = Ui_Login()
window.show()
app.exec_()