"""Test evaluate_hasti_pro on 10 financial queries."""
from evaluate_hasti_pro import evaluate_hasti_pro

test_cases = [
    ("ارزش آتی مبلغ اولیه 1000 با نرخ سود 5 درصد در مدت 3 سال چند است؟", 1157.63),
    ("سود ساده برای اصل پول 2000 با نرخ 4 درصد و مدت 2 سال چقدر است؟", 160.0),
    ("تغییر درصدی از مقدار 100 به مقدار 150 چند درصد است؟", 50.0),
    ("باقیمانده تقسیم عدد 17 بر عدد 5 چند است؟", 2.0),
    ("حاشیه سود با درآمد کل 5000 و بهای تمام شده 3000 چند درصد است؟", 40.0),
    ("میانگین وزنی دو عدد 10 با وزن 2 و 20 با وزن 3 چند است؟", 16.0),
    ("درصد تخفیف برای قیمت اصلی 200 و قیمت پرداختی 150 چند است؟", 25.0),
    ("ارزش فعلی مبلغ آینده 1000 با نرخ تنزیل 5 درصد در مدت 2 سال چند است؟", 907.03),
    ("انحراف معیار اعداد 2 و 4 و 6 چند است؟", 1.63),
    ("نمره استاندارد برای مقدار 85 با میانگین 70 و انحراف معیار 10 چند است؟", 1.5),
]

print("=" * 60)
print("TESTING evaluate_hasti_pro")
print("=" * 60)

passed = 0
for i, (query, expected) in enumerate(test_cases, 1):
    result = evaluate_hasti_pro(query)
    if isinstance(result, (int, float)):
        ok = abs(result - expected) < 0.1
    else:
        ok = False
    if ok:
        passed += 1
    print(f"{'OK' if ok else 'FAIL'} | Q{i}: {query[:60]}")
    print(f"     Result: {result}, Expected: {expected}")

print()
print(f"PASSED: {passed}/{len(test_cases)}")
