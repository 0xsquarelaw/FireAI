import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Sending data
email = 'anomaliquintusbot@gmail.com'
password = 'Hackaton2024'

#Adressee details
to_email = 'tonovera3@gmail.com'

# Set the message
subject = 'Proof'
body = 'Hello this is an email test'

msg = MIMEMultipart()
msg['From'] = email
msg['To'] = to_email
msg['Subject'] = subject
msg.attach(MIMEText(body, 'plain'))

# Log in to the SMTP server
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login(email, password)

# Send an e-mail
server.sendmail(email, to_email, msg.as_string())

#Close connection
server.quit()
