# SSL-domain-scanner
Тестовое задание на позицию Junior Java Developer

Требуется разработать приложение, которое сканирует диапазон IP адресов и выводит все найденные доменные имена, которые присутствуют в SSL сертификатах данных IP адресов, если они есть.
На вход подается диапазон IP адресов с маской, например, 51.38.24.0/24 (51.38.24.0-51.38.24.255). Также указывается кол-во потоков. Приложение должно равномерно распределить между потоками IP адреса, которые предстоит просканировать, и выполнить само сканирование. Для каждого IP адреса необходимо получить SSL сертификат, если он есть, и выполнить в теле сертификата поиск любых доменов. Все найденные домены сохранить в текстовый файл. Программа должна иметь web-интерфейс, через который происходит все взаимодействие пользователя с приложением.
Требования:
– Java 8
– Фреймворк для веб-запросов: Apache Http Client
– Фреймворк для веб-интерфейса: Javalin
– Maven
– Spring Framework использовать запрещается.
– Фронт либо на чистом HTML&CSS, либо на Bootstrap5. React, Angural и т. д. использовать запрещается.
На выполнение задания дается 7 дней с настоящего момента. Просьба прислать готовое задание на почту armen.krylov@internet.ru
