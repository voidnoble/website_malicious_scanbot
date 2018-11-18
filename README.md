웹페이지 위변조 감시, 감지시 슬랙 알림

# Setting

index.js, article.js, article_instant.js 의 아래 "" 값 설정.

```
// 알림 받을 슬랙 웹훅 URL
const webHookUrl = "https://hooks.slack.com/services/xxxxxxxxxx/xxxxxxxxx/xxxxxxxxxxxxxxxx";
...
// 위변조 감시할 페이지 URL
await page.goto("http://www.domain.com/article/G1110879371");
```

# Execute

## Production

1. cd /home/nodejs/website_malicious_scanbot
2. nohup node index.js >> /var/log/website_malicious_scanbot.log &
3. nohup node article.js >> /var/log/website_malicious_scanbot.log &
4. nohup node photo_slide.js >> /var/log/website_malicious_scanbot.log &

# Manage background jobs

## List
* jobs -l

```
[1]- 13198 Running    nohup node index.js >> /var/log/website_malicious_scanbot.log &
[2]+ 13213 Running    nohup node article.js >> /var/log/website_malicious_scanbot.log &
[3]+ 13214 Running    nohup node photo_slide.js >> /var/log/website_malicious_scanbot.log &
```

## Kill
* kill %1
* kill %2
* kill %3

## To Foreground
* fg %1
* fg %2
* fg %3

## To Background
* bg %1
* bg %2
* bg %3

# Log

## Production

tailf /var/log/website_malicious_scanbot.log
