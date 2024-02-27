import base64
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich import print
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.style import Style

SAFE_FOLDER_PATH = 'encrypted_data'
FILE_EXTENSION = '.pjcd'

default_style = Style(color="white", bold=True)


def aes_encrypt(plain_text, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted_data).decode()


def aes_decrypt(encrypted_data, password):
    decoded_data = base64.b64decode(encrypted_data.encode())
    salt = decoded_data[:16]
    iv = decoded_data[16:32]
    encrypted_data = decoded_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data.decode()
    except ValueError:
        return


def json_read(file_path) -> list[str]:
    with open(file_path) as file:
        return json.load(file)


def json_create(file_path, data: list[str]):
    with open(file_path, "w") as file:
        json.dump(data, file)


def main_loop():
    file_paths = []
    if os.path.exists(SAFE_FOLDER_PATH):
        for root, dirs, files in os.walk(SAFE_FOLDER_PATH):
            for file in files:
                if file.endswith(FILE_EXTENSION):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, SAFE_FOLDER_PATH)
                    file_paths.append(relative_path)
    else:
        os.makedirs(SAFE_FOLDER_PATH)
    if len(file_paths) > 0:
        i = 1
        text = ""
        first = True
        for file_path in file_paths:
            if first:
                first = False
            else:
                text += f"\n"
            text += f"{i}.\t{file_path}"
            i += 1
        print(Panel(text, title="Сейфы", highlight=True, expand=False, style=default_style))
        safe_num = IntPrompt.ask(
            "Выберите сейф или нажмите Enter для создания нового",
            choices=[str(y) for y in range(1, i)],
            default=0,
            show_default=False,
            show_choices=False)
        if not safe_num:
            create_safe()
        else:
            file_name = file_paths[safe_num - 1]
            open_safe(file_name)
    else:
        print(f"[red]Файлы с расширением {FILE_EXTENSION} не найдены.[red]")
        create_safe()


def open_safe(file_name: str):
    safe_data = json_read(f"{SAFE_FOLDER_PATH}/{file_name}")
    password = ""
    question_count = len(safe_data) - 1
    for i, question in enumerate(safe_data[1:]):
        password += Prompt.ask(f"[green]Вопрос {i + 1} из {question_count}: {question}[green]")
    decrypt_result = aes_decrypt(safe_data[0], password)
    if decrypt_result:
        print("Результат дешифровки:")
        print(f"[black on white]{decrypt_result}[black on white]")
    else:
        print("[white on red]Ошибка. Данные дешифровки неверны.[white on red]")


def create_safe():
    question = ""
    answer = ""
    questions = []
    answers = []
    print("Создаем новый сейф. Введите произвольное кол-во вопросов и ответов (пустой ввод, чтобы закончить)."
          " [red]Внимание! Ответы чувствительны к регистру.[red]")
    i = 1
    while True:
        question = Prompt.ask(f"[green]Вопрос {i}[green]")
        if not question:
            break
        answer = Prompt.ask(f"[green]Ответ {i}[green]")
        if not answer:
            break
        questions.append(question)
        answers.append(answer)
        i += 1
    print("[cyan]Ввод вопросов завершен, введите текст для шифрования...[cyan]"
          " [yellow](используйте ### для завершения)[yellow]\n")
    lines = []
    while True:
        line = Prompt.ask()
        if line != "###":
            lines.append(line)
        else:
            break
    multiline_text = '\n'.join(lines)
    text_encrypted = aes_encrypt(multiline_text, ''.join(answers))
    container = [text_encrypted] + questions
    print()
    path = f"{SAFE_FOLDER_PATH}/{Prompt.ask('Назовите файл')}{FILE_EXTENSION}"
    json_create(path, container)


if __name__ == '__main__':
    while True:
        main_loop()
