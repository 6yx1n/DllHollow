# DllHollow
DLL空心化的核心思想是“借壳执行”，即利用系统中已存在的合法DLL作为载体，通过修改其代码区域，将自定义功能代码（Payload）注入其中，借助系统对可信DLL的信任机制，实现Payload的隐蔽加载与执行。相较于传统的代码注入技术，其优势在于载体本身具有系统合法性，可有效规避安全软件对未知代码的拦截与检测。

<img width="2304" height="830" alt="image" src="https://github.com/user-attachments/assets/5c6e11c3-5da5-4c51-960c-128a73f5a4d6" />
<img width="2534" height="1416" alt="image" src="https://github.com/user-attachments/assets/20b4ed32-81c1-41c8-8699-2aa29017c83b" />
<img width="2300" height="1203" alt="image" src="https://github.com/user-attachments/assets/0eec41ad-ba7d-4f36-81be-1f94d327e834" />
![Uploading image.png…]()
