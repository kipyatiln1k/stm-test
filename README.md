# Алгоритм поиска минимальной подсети для заданного набора IP-адресов  

## Использование
**Версия Python: 3.6.8**

```shell
python subnet.py [имя_файла] (ipv4 | ipv6)
```

имя_файла - название файла, где хранится список ip-адресов, разделённых переносом строки. 

ipv4, ipv6 - возможные типы ip-адресов

## Алгоритм
**Сложность: O(n)**

1. Если в файле один уникальный IP - возвращаем подсеть c этим адресом и максимальной длинной маски
2. Применяем побитовое "И" между всеми адресами в файле
3. Создаём список из чисел, которые являются результатом применения побитового "исключающего ИЛИ" между результатом этапа **2** и каждым из наших адресов. 
4. Выбираем максимальное число из результата этапа 3. Если представить это число в виде 32-значного двоичного числа, где незадействованные старшие разряды заняты нулями, то его первая единица будет стоять на месте первого нуля маски. (Все разряды маски оказались заняты нулями в результате поразрядного "исключающего ИЛИ").
5. Длина префикса = максимальная длина префикса - результат этапа 4.
6. Создаём маску с длиной префикса, получившейся на этапе 5, и применяем поразрядное "И" между ней и результатом этапа 2. 
7. Возвращаем подсеть с адресом 6 и длиной префикса 5. 
