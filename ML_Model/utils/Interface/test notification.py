import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Gmail SMTP server configuration
smtp_server = 'smtp.gmail.com'
smtp_port = 587  #TLS connections port

# Email address of the sender and recipient
from_email = 'xitope3828@adstam.com'
to_email = 'tonovera3@gmail.com'

# Your Gmail and Password account (you must enable the access of less safe applications in your Gmail account)
gmail_username = 'xitope3828@adstam.com'
gmail_password = 'Hackaton2024'

# Create the object of the message
message = MIMEMultipart()
message['From'] = from_email
message['To'] = to_email
message['Subject'] = 'Mail subject'

# Mail content
body = "Hello, \ n \ neste is a trial email sent from python."

# Attach the body of the mail
message.attach(MIMEText(body, 'plain'))

# Start connection to Gmail SMTP server
server = smtplib.SMTP(smtp_server, smtp_port)
server.starttls()

# GMAIL SMTP server
server.login(gmail_username, gmail_password)

# Send email
server.sendmail(from_email, to_email, message.as_string())

# Close the connection to the Gmail SMTP server
server.quit()

print('Mail sent successfully.')
