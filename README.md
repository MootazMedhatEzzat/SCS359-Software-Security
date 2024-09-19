# SCS359-Software-Security

---
<div align="center">
  <table width="100%">
    <tr>
      <td colspan="2" align="center"><strong>{ Digital Signatures Presentation }</strong></td>
    </tr>
    <tr>
      <td align="center"><strong>Names:</strong><br>Dalia Gamal Abdelhamed<br>Mootaz Medhat Ezzat Abdelwahab</td>
      <td align="center"><strong>IDs:</strong><br>20206023<br>20206074</td>
    </tr>
    <tr>
      <td align="left"><strong>Program</strong>: Software Engineering</td>
      <td align="right"><strong>Group</strong>: B (S5)</td>
    </tr>
    <tr>
      <td colspan="2" align="center"><strong>Delivered To</strong>: Dr. Basheer Abdel Fatah Youssef</td>
    </tr>
  </table>
</div>

---

![image](https://github.com/user-attachments/assets/2b1bae8b-3c25-4d76-8d45-e8fbdc747221)
![image](https://github.com/user-attachments/assets/8ed0c5ea-ef22-4b03-97a2-0fb5bff7b7d3)
![image](https://github.com/user-attachments/assets/e74f9c77-cbbf-42a0-a62b-8926d7439f66)
![image](https://github.com/user-attachments/assets/c8b33ef8-de66-4f25-b159-e7ad10815783)

## 📄 Presentation Description

Cairo University  
Faculty of Computers and Artificial Intelligence  
Software Security Course (Spring 2024)

This presentation is a comprehensive overview of Digital Signatures, a secure way to authenticate and verify the integrity of digital messages and documents. It covers the fundamental concepts of traditional signatures, electronic signatures, and dives deep into digital signatures. The presentation explains how digital signatures work, the benefits of using them, and the cryptographic techniques involved. Attendees will understand the role of certificate authorities (CAs) and the process of obtaining and verifying digital signatures. This presentation is part of the term work for the Software Security course taught by Dr. Basheer Abdel Fatah Youssef at the Faculty of Computers and Artificial Intelligence, Cairo University.

## 🔐 How does a Digital Signaturework?
![image](https://github.com/user-attachments/assets/1b87f754-8090-40b4-8961-7971c2f9f458)
![image](https://github.com/user-attachments/assets/8f268d55-941c-42c2-b025-2fe9d364be72)

**1️⃣ Alice Obtains a Digital Certificate from a CA (Certificate Authority)**:
- 🗝️ Alice generates a public-private key pair.
- 📜 Alice submits her public key and identity information to a CA, requesting a digital certificate.
- 🔍 The CA verifies Alice's identity (checking government databases, contacting Alice's employer).
- ✅ Once Alice's identity is verified, the CA creates a digital certificate. This certificate includes Alice's public key, Alice's identity information, the CA's identity, and a digital signature from the CA.
![image](https://github.com/user-attachments/assets/2655ab5d-90d2-4abb-9bbe-e5f45a15e2dd)

**2️⃣ Alice Digitally Signs the Message:**
- 💬 Alice writes her message, let's say "Hello, Bob!".
- 🔑 Alice uses a hashing algorithm (e.g., SHA-256) to generate a hash of the message. This is a fixed-size string that uniquely represents the message content.
- 🔏 Alice encrypts the hash using her private key, producing the digital signature.
- ✉️ Alice sends the original message "Hello, Bob!" attached with the digital signature, and her digital certificate to Bob.
![image](https://github.com/user-attachments/assets/31ab8089-b5df-4ca5-adce-0d5457675529)

**3️⃣ Bob Verifies the Digital Signature:**
- 🛡️ Bobv erifies that the digital certificate is valid and has been issued by a trusted CA.
- 🔑 Assuming the certificate is valid, Bob extracts Alice's public key from it.
- 🧮 Bob uses the same hashing algorithm(e.g.,SHA-256)to generate a hash of the received message "Hello, Bob!".
![image](https://github.com/user-attachments/assets/75cd6b38-8ce7-4439-aee8-c7cc6a79fe0c)

**3️⃣ Bob Verifies the Digital Signature:**
- 🔓 Bob  ecrypts the digital signature using Alice's public key, which should give him thehashthat Alice originally generated..
- 🧐 Bob compares thehashhe generated from the message with the decrypted hash.
![image](https://github.com/user-attachments/assets/03bd10ed-57d1-4030-b5b2-582a3231044b)
- If the two hashes match, Bob can trust that the message came from Alice and that it hasn't been tampered with! 💼🔒

---

## 💬 Let's Connect
Feel free to reach out to me if you'd like to collaborate on a project or discuss technology! As a Software Engineer, I'm always open to tackling new challenges, sharing knowledge, and growing through collaborative opportunities.

**Mootaz Medhat Ezzat Abdelwahab**  
🎓 Software Engineering Graduate | Faculty of Computers and Artificial Intelligence, Cairo University  

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/mootaz-medhat-ezzat-abdelwahab-377a60244)
