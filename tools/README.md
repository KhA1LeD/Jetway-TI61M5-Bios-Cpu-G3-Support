# أدوات تعديل البيوس (Jetway TI61M5)

`bios_ucode.py` يفحص ويعدّل الـ microcode داخل ملف البيوس بدون أي مكتبات خارجية.

```
python3 tools/bios_ucode.py audit    "Jetway TI61M5.bin"
python3 tools/bios_ucode.py patch    "Jetway TI61M5.bin" --ucode-dir intel-ucode -o patched.bin
python3 tools/bios_ucode.py verify   "Jetway TI61M5.bin" patched.bin
python3 tools/bios_ucode.py selftest "Jetway TI61M5.bin"
```

## ما الذي يحتويه الملف الأصلي (نتيجة الفحص)

- نسختان متطابقتان من microcode: واحدة في الـ FV غير المضغوط (PEI) وأخرى داخل قسم LZMA (DXE).
- فيهما معرّفات الجيل الثالث (Ivy Bridge): `306A2 / 306A4 / 306A5 / 306A6 / 306A8 / 306A9`، إضافةً إلى الجيل الثاني `206A6 / 206A7`.
- يحتوي أيضًا على `IntelIvbGopDriver` بجانب `IntelSnbGopDriver`.
- أي أن الملف يبدو مهيّأً أصلًا للجيل الثالث؛ أحدث إصدار فيه لـ `306A9` هو `0x19` (2013).

## ما يفعله الـ Action

مسار: **Actions → BIOS - Gen3 (Ivy Bridge) microcode → Run workflow**

1. اختبار ذاتي للأداة.
2. فحص الملف قبل التعديل.
3. تنزيل أرشيف المصدر لآخر إصدار من `intel/Intel-Linux-Processor-Microcode-Data-Files` (الإصدارات لا تحمل ملفات مرفقة، فقط أرشيف الكود).
4. استبدال microcode الجيل الثالث بإصدار أحدث **في نفس المكان وبنفس الحجم** في النسختين، مع إعادة ضغط LZMA وإصلاح checksums الـ FFS.
5. فحص وتحقق بعد التعديل (`verify`)، ثم مقارنة إضافية بـ UEFIExtract (UEFITool) إن توفر.
6. رفع الملف الناتج وتقارير الفحص كـ artifact باسم `gen3-bios`.

الـ Action لا يكتب فوق الملف الأصلي في المستودع.

## حدود

- لا يمكن التحقق من الإقلاع الفعلي من الملف وحده (ME / MRC / VBIOS / إعدادات اللوحة). احتفظ بنسخة احتياطية وبرمجة خارجية (CH341A) قبل أي تفليش.
- إن كان حجم الـ microcode الجديد يختلف عن الخانة الموجودة، يُتجاهل ويُسجَّل في `patch.log`، لأن التوسعة تتطلب إعادة ترتيب الـ FV.
