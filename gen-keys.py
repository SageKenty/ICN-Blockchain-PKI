from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import os

# 鍵を生成
sk = ed25519.Ed25519PrivateKey.generate()
pk = sk.public_key()

# ===== 秘密鍵をPEM形式で保存 =====
with open("ed25519_bcnode3_sk.pem", "wb") as f:
    f.write(
        sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # パスワードなし
        )
    )

# ===== 公開鍵をPEM形式で保存 =====
with open("ed25519_bcnode3_pk.pem", "wb") as f:
    f.write(
        pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("Key Gen Completed !!")