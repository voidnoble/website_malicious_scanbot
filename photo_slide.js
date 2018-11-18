const puppeteer = require('puppeteer');
const cheerio = require('cheerio');
const cron = require('node-cron');
const { IncomingWebhook } = require('@slack/client');
const webHookUrl = "https://hooks.slack.com/services/XXXXXXXX0/XXXXXXXXX/xxxxxxxxxxxxxxxxxxxxxxx";
const webhook = new IncomingWebhook(webHookUrl);

// Execute every 20 min
cron.schedule('*/20 * * * *', () => {
    (async() => {
        const browser = await puppeteer.launch({
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox'],
        });
        const page = await browser.newPage();
        try {
            await page.goto("http://www.domain.com/photo/slide_view/1862");
        } catch (exception) {
            console.log(exception);
            await browser.close();
            return;
        }
        const body = await page.evaluate(() => document.body.outerHTML);
        const $ = cheerio.load(body);
        let msg = "";
        let isSafe = "YES";
        let functionPattern = /function (\w+) ?\(/g;
        const functionWhitelists = ["goto_tab","showFlash","getFlashHtml","hideTopBanner","jq__slideUpAndRemove","isMsIe","isMsIe11","open_win","close_win","scroll_realtimenews","openPopup","pre_img","next_img","set_slide","img_resize","comment_length_check","submit_comment_form","print_article","get_last_page","goto_page","get_order","get_news","set_sel_img","gisano_to_order","order_to_gisano","slide_start","pre_img","next_img","img_resize","twitter_login","facebook_login","me2day_login","sns_login_success","Prism_PlayerSetting","responseAdparamData","setPlayData","Prism_onStateEventHandler","Prism_finishEventHandler","newsTab","categoryArticles"];
        
        const scriptSrcWhitelistPattern = /www\.google-analytics\.com|www\.googletagmanager\.com|www\.googletagservices\.com|ajax\.googleapis\.com|adservice\.google\.com|adservice\.google\.co\.kr|securepubads\.g\.doubleclick\.net|cdnjs\.cloudflare\.com|compass\.adop\.cc|de\.tynt\.com|cdn\.tynt\.com|whos\.amung\.us|t\.dtscout\.com|js\.keywordsconnect\.com|js2\.keywordsconnect\.com|cm\.keywordsconnect\.com|waust\.at|mktag\.mt\.co\.kr|ssp\.realclick\.co\.kr|interface\.interworksmedia\.co\.kr|cm\.interworksmedia\.co\.kr|ds\.interworksmedia\.co\.kr|ps\.eyeota\.net|n-cdn\.areyouahuman\.com|t\.dtscdn\.com|ad\.impactify\.io|api\.dmcdn\.net|ad\.3dpop\.kr|static\.image2play\.com/;

        const scripts = $('script');
        let footerNextScript = $('#footer + script').html();

        // 날짜 구하기
        let date = new Date();
        let year = date.getFullYear();
        let month = new String(date.getMonth() + 1);
        let day = new String(date.getDate());
        let hour = new String(date.getHours());
        let minute = new String(date.getMinutes());
        let sec = new String(date.getSeconds());
        // 한자리수일 경우 0을 채워준다. 
        if (month.length == 1) month = "0" + month;
        if (day.length == 1) day = "0" + day;
        if (minute.length == 1) minute = "0" + minute;
        if (sec.length == 1) sec = "0" + sec;
        // 현재 날짜
        let now = year + "-" + month + "-" + day + " " + hour + ":" + minute + ":" + sec;

        // Case 001
        if (footerNextScript) {
            isSafe = (/^[ \n]+\/\/<!\[CDATA\[/.test(footerNextScript))? "YES" : "NO";
            if (isSafe == "NO") {
                msg = "웹사이트 /photo/slide_view/1862 에 Case 001 악성코드 삽입 감지됨!";
                webhook.send(msg, (err, res) => {
                    if (err) {
                        console.log('Error:', err);
                        return;
                    }

                    console.log('Message sent: ', res);
                });
            }
        }

        // Case 002
        msg = "";
        isSafe = "YES";  // init
        $(scripts).each((i, script) => {
            if (/(","[^"]+){10,}/.test($(script).html())) {
                isSafe = "NO";
                return;
            }
        });
        if (isSafe == "NO") {
            msg = "웹사이트 /photo/slide_view/1862 에 Case 002 악성코드 삽입 감지됨!";
            webhook.send(msg, (err, res) => {
                if (err) {
                    console.log('Error:', err);
                    return;
                }

                console.log('Message sent: ', res);
            });
        }

        // Case 003
        // functionPattern 으로 함수명들 추출 뒤 functionWhitelists 와 비교하여 없는거면 isSafe = "NO"
        msg = "";
        isSafe = "YES";  // init
        let scriptHTML = "";
        $(scripts).each((i, script) => {
            scriptHTML += $(script).html();
        });
        let functionNames = scriptHTML.match(functionPattern);
        for (let i = 0; i < functionNames.length; i++) {
            let functionNameSrc = functionNames[i];
            let functionName = functionNameSrc.replace(functionPattern, "$1");
            //console.log(functionName +"\n");
            if (functionWhitelists.indexOf(functionName) === -1) {
                //console.log(functionName);
                msg = `function ${functionName}()`;
                isSafe = "NO";
                break;
            }
        }
        if (isSafe == "NO") {
            msg = "웹사이트 /photo/slide_view/1862 에 Case 003 악성코드 삽입 감지됨!"+ msg;
            webhook.send(msg, (err, res) => {
                if (err) {
                    console.log('Error:', err);
                    return;
                }

                console.log('Message sent: ', res);
            });
        }

        // Case 004
        // script 태그들의 src 속성값들과 scriptSrcWhitelists 와 비교하여 없는거면 isSafe = "NO"
        msg = "";
        isSafe = "YES";  // init
        let scriptSrc = "";
        $(scripts).each((i, script) => {
            scriptSrc = $(script).attr("src");
            if (typeof scriptSrc != "undefined" && scriptSrc != "undefined" && scriptSrc != "") {
                // Whistlist 에 없는 script src 속성이면
                if (!scriptSrcWhitelistPattern.test(scriptSrc)) {
                    msg = `script src="${scriptSrc}"`;
                    isSafe = "NO";
                    return false;   //= break
                }
            }
        });
        if (isSafe == "NO") {
            msg = "웹사이트 /photo/slide_view/1862 에 Case 004 악성코드 삽입 감지됨!" + msg;
            webhook.send(msg, (err, res) => {
                if (err) {
                    console.log('Error:', err);
                    return;
                }

                console.log('Message sent: ', res);
            });
        }

        console.log(`[${now}] /photo/slide_view/1862 Is safe? ${isSafe}`);
        await browser.close();
    })();
});
