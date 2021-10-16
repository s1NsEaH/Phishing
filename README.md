# Phishing 
피싱 의심 사이트 탐지기법 - 작성중(초안)

개요. 
피싱 사이트란 실제와 유사한 웹 페이지를 통해 사용자의 개인정보 및 금융정보를 요구한 뒤 각종 공격, 특히 금전적 피해를 일으키는 사기 수법을 말합니다.

피싱 웹사이트는 유사 도메인 또는 해킹된 웹사이트에서 호스팅되고 있습니다.
연방 수사국 FBI(https://www.ic3.gov/Media/PDF/AnnualReport/2020_IC3Report.pdf)는 피싱이 사이버 범죄자가 수행하는 가장 일반적인 공격이라 설명하며. 2016년에 비해 2020년에 피싱 신고가 11배 이상 증가했다고 말했습니다.
또한, 국내는 경찰통계연보 보고서에 따르면 2018년에 비해 2019년의 피싱 발생 건수가 약 45%, 피해액은 약 51% 증가했습니다.

피싱은 매년 증가 추세를 보였고, 공격 빈도는 산업별로 상이하지만, 그 중 금융분야 3위를 차지하고 있습니다.

본 글은 참가기관 곧, 금융회사 홈페이지를 사칭한 피싱 의심 사이트를 초기에 탐지하고 차단하여 금융소비자 대상 사기 피해를 예방하기 위한 목적으로 탐지 기법을 소개합니다.

1. 퍼징을 이용한 피싱 탐지

퍼징은 일반적으로 프로그램에 임의의 데이터를 입력하고 결과를 분석하여 잠재적으로 악용 가능한 버그를 찾는 자동화된 프로세스를 말합니다.

퍼징을 통해 입력 데이터에 조금씩 변이를 주어 새로운 입력 데이터를 생성하고, 무작위한 데이터의 조정 및 피싱 사이트를 참가기관을 대상으로 한정 짓기 위해 사이버 스쿼팅으로 활용될 수 있는 도메인을 생성하고자 합니다.

사이버 스쿼팅이란 상표, 서비스 마크, 회사 이름 또는 개인 이름과 동일하거나 유사한 인터넷 도메인 이름의 무단 등록 및 사용을 의미하며, 이는 합법적인 브랜드의 소유라고 믿도록 유도하고 피싱 및 사기 캠페인의 효율성을 높이기 때문에, 피싱에서 인기 있는 위협 중 하나입니다.

사이버 스쿼팅은 공격 대상 사이트의 도메인을 유사 도메인으로 점유하는 특징때문에, 공격 대상을 특정 지을 수 있습니다.


[데이터 생성]

1. 비트스쿼팅
Bitsquatting은 컴퓨터 오류(비트 플립) 으로 알려진 1비트 오류 즉, 메모리의 임의 오류로 발생하기 때문에
공격자는 사용자가 방문하려는 웹사이트와 1비트 다른 웹사이트를 등록할 수 있습니다.
예를 들면 shinhan.com 도메인에서 문자 's'(01110011)와 1비트 다른 whinhan.com('01110111' == 'w') 도메인이 공격에 사용될 수 있습니다.

2. 동형문자 치환
동형 문자는 한 문자 집합의 상형 문자 또는 문자가 다른 문자 집합의 문자 모양과 동일하게 보이는 경우입니다. 
예를 들어 키릴 문자의 소문자 "а"는 유니코드 키릴 문자의 소문자 "a"와 동일한 것처럼 보이지만, 컴퓨터의 경우에는 매우 다릅니다.
동형문자는 사람의 눈으로 식별할 수 없기 때문에 피싱 공격에 자주 사용될 수 있습니다.

해당 주소를 접근하게 되면 전혀 다른 도메인으로 리다이렉션됩니다.
http://xn--shinhn-7nf.com/

3. 하이픈(hyphen) 삽입
S. Carolin Jeeva 저자의 'Intelligent phishing url detection using association rule mining' 논문에서 드물게 정상 사이트의 경우 최대 1개의 하이픈을 가지는 것으로 확인되며, 이에 따라 공격자는 사용자가 정상 사이트로 오인하도록 하이픈을 피싱 도메인에 이용할 수 있습니다.

4. 입력 문자 제거, 추가, 반복 및 치환
입력 값의 변이 정도 기준은 편집거리 알고리즘에 대한 결과 값 1로 산정했습니다.
예를 들면 입력 값 'shinhan.com'에서 문자 's'를 제거하고 추가한 'hinhan.com', 'sshinhan.com'의 편집거리 결과는 모두 1입니다.
편집 거리 알고리즘이란, 두 개의 문자열이 같아지기 위해서 몇 번의 추가, 편집, 삭제가 이루어져야 하는지에 대한 최소 개수를 구하는 알고리즘입니다.

5. 입력 문자 대치
입력 문자 대치는 타이포스쿼팅에 기반하여 사용자가 도메인 입력 시 입력 키 기준으로 잘못 입력할 수 있는 근접한 키로 대치합니다. 해당 키 배열의 기준은 QWERTY 자판과, 천지인 자판으로 선정하였다.

타이포 스쿼팅이란, 웹 브라우저 URL 필드에 실수로 웹 사이트 주소를 직접 잘못 입력하는 사람들을 대상으로 하는 사이버 스쿼팅의 한 형태입니다.

*QWERTY 자판(쿼티 자판)은 영어 타자기나 컴퓨터 자판에서 가장 널리 쓰이는 자판 배열이다. 자판의 왼쪽 상단의 여섯 글자를 따서 이름 붙여졌다
*천지인 자판은 휴대전화 입력기 중 하나로 피쳐폰 시절 삼성전자와 KT테크의 휴대 전화에 장착되었으며, 국가 표준 입력기이자 국제 표준 입력기로 지정되었다


6. 하위 도메인
입력 값에 대해 구두점를 생성하여 하위 도메인을 만듭니다. Shafaizal Shabudin 외 3명 'Feature Selection for Phishing Website Classification' 학술 저널 연구에서 피싱 탐지를 위해 특징을 평가한 30개 목록 중 Subdomain은 4위를 기록했다.

7. 모음 치환
입력 값에서 모음을 다른 모음으로 치환했으며, 이러한 도메인 중 상당수가 대부분의 사용자를 속여 사기성 링크를 클릭하도록 만들 수 있습니다.

8. TLD 치환
보안 기업 Bolster의 2021년 State of Phishing& Online Fraud 보고서에서 나타난 피싱에 흔히 이용된 TLD 상위 10 목록을 대상으로 입력 도메인의 TLD와 치환합니다.

[피싱 사이트 특징 추출]
1. SSL 인증서 정보

2. DNS 등록 정보

3. 메일 서버 유무

4. 웹 타이틀 정보



2. 공개 인텔리전스를 활용한 피싱 탐지

https://raw.githubusercontent.com/rpaditya/rtbh/master/etc/domain/http%3A..data.phishtank.com.data.online-valid.csv



[참고 자료]
https://bolster.ai/resources-center/download/report/2021-phishing-online-fraud?utm_source=blog&utm_medium=web&utm_campaign=2021-phishing-report&utm_content=2021-phishing-online-fraud / 금융 섹터 피싱 위협 순위 참조
https://manuscriptlink-society-file.s3-ap-northeast-1.amazonaws.com/kips/conference/kips2020spring/KIPS_C2020A0162.pdf / 최근 퍼징 기법들과 발전에 관한 연구
http://eprints.hud.ac.uk/id/eprint/24330/6/MohammadPhishing14July2015.pdf / Phishing Websites Features
https://www.fuzzingbook.org/html/MutationFuzzer.html / Mutation-Based Fuzzing
https://sec.okta.com/articles/2020/11/why-bitsquatting-attacks-are-here-stay / Why Bitsquatting Attacks Are Here to Stay
Hunting Cyber Criminals: A Hacker's Guide to Online Intelligence Gathering Tools and Techniques
https://thesai.org/Downloads/Volume11No4/Paper_77-Feature_Selection_for_Phishing_Website.pdf / Feature Selection for Phishing Website Classification
