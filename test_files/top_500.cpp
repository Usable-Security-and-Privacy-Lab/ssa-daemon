#include <gtest/gtest.h>

#include <future>
#include <stdlib.h>
#include <string>

extern "C" { // To indicate that the code is C code when linking--important
#include "helper_functions.h"
}

#define TEST_TIMEOUT_BEGIN  std::promise<bool> promisedFinished; \
                            auto futureResult = promisedFinished.get_future(); \
                            std::thread([&](std::promise<bool>& finished) {

/// X is in milliseconds
#define TEST_TIMEOUT_FAIL_END(X)  finished.set_value(true); \
                                  }, std::ref(promisedFinished)).detach(); \
                                  bool testTimedOut = futureResult.wait_for(std::chrono::milliseconds(X)) == std::future_status::timeout; \
                                  EXPECT_FALSE(testTimedOut);

#define TEST_TIMEOUT_SUCCESS_END(X) finished.set_value(true); \
                                    }, std::ref(promisedFinished)).detach(); \
                                    bool testTimedOut = futureResult.wait_for(std::chrono::milliseconds(X)) == std::future_status::timeout; \
                                    EXPECT_TRUE(testTimedOut);

// Each connection should DEFINITELY take less than 4 seconds to run
#define TIMEOUT 4000 


extern "C" {

#define HTTPS_PORT "443"

}

#define RUN_TEST(test_label, hostname)                                          \
    TEST_F(Top500WebsitesTest, test_label) {                                    \
                                                                                \
        TEST_TIMEOUT_BEGIN                                                      \
        std::string str = hostname;                                             \
        result = run_http_client(str.c_str(), HTTPS_PORT, &resp, &resp_len);    \
        EXPECT_EQ(result, (int) E_SUCCESS);                                     \
                                                                                \
        TEST_TIMEOUT_FAIL_END(TIMEOUT)                                          \
    }                                                                   



class Top500WebsitesTest : public testing::Test {
public:
    char *resp;
    int resp_len;
    int result;

    virtual void SetUp() {
        resp = NULL;
        resp_len = 0;
        result = 0;
    }

    virtual void TearDown() { }
};

// 150ish of the top websites

RUN_TEST(Google, "www.google.com")
RUN_TEST(Facebook, "facebook.com")
RUN_TEST(Youtube, "youtube.com")
RUN_TEST(Yahoo, "yahoo.com")
RUN_TEST(Twitter, "twitter.com")
RUN_TEST(Amazon, "amazon.com")
RUN_TEST(Ebay, "ebay.com")
RUN_TEST(CNN, "cnn.com")
RUN_TEST(LinkedIn, "linkedin.com")
RUN_TEST(Pinterest, "pinterest.com")
RUN_TEST(NYTimes, "nytimes.com")
RUN_TEST(Wikipedia, "wikipedia.org")
RUN_TEST(Bing, "bing.com")
RUN_TEST(Apple, "apple.com")
RUN_TEST(Weather, "weather.com")
RUN_TEST(MSN, "www.msn.com");
RUN_TEST(Microsoft, "microsoft.com")
RUN_TEST(Wordpress, "wordpress.com")
RUN_TEST(AOL, "aol.com")
RUN_TEST(Tumblr, "tumblr.com")
RUN_TEST(HuffingtonPost, "huffingtonpost.com")
RUN_TEST(Live, "live.com")
RUN_TEST(Flickr, "flickr.com")
RUN_TEST(Etsy, "etsy.com")
RUN_TEST(Paypal, "paypal.com")
RUN_TEST(IMDB, "imdb.com")
RUN_TEST(Blogspot, "blogspot.com")
RUN_TEST(Ask, "ask.com")

/*
RUN_TEST(About, "about.com")
RUN_TEST(Reddit, "reddit.com")
RUN_TEST(Pandora, "pandora.com")
RUN_TEST(BBC, "bbc.co.uk")
RUN_TEST(NFL, "nfl.com")
RUN_TEST(Walmart, "walmart.com")
RUN_TEST(USAToday, "usatoday.com")
RUN_TEST(FoxNews, "foxnews.com")
RUN_TEST(Dropbox, "dropbox.com")
RUN_TEST(NewEgg, "newegg.com")
RUN_TEST(Craigslist, "craigslist.com")
RUN_TEST(SwagBucks, "swagbucks.com")
RUN_TEST(NBCNews, "www.nbcnews.com")
RUN_TEST(Hulu, "hulu.com")
RUN_TEST(CNet, "cnet.com")
RUN_TEST(eHow, "ehow.com")
RUN_TEST(Como, "como.com")
RUN_TEST(DeviantArt, "deviantart.com")
RUN_TEST(Vimeo, "vimeo.com")
RUN_TEST(Adobe, "adobe.com")
RUN_TEST(WashingtonPost, "washingtonpost.com")
RUN_TEST(Target, "target.com")
RUN_TEST(NBA, "nba.com")
RUN_TEST(BestBuy, "bestbuy.com")
RUN_TEST(StumbleUpon, "stumbleupon.com")
RUN_TEST(Gizmodo, "gizmodo.com")
RUN_TEST(Politico, "politico.com")
RUN_TEST(StackOverflow, "stackoverflow.com")
RUN_TEST(Wired, "wired.com")
RUN_TEST(SoundCloud, "soundcloud.com")
RUN_TEST(MediaFire, "mediafire.com")
RUN_TEST(HootSuite, "hootsuite.com")
RUN_TEST(GoDaddy, "godaddy.com")
RUN_TEST(Netflix, "netflix.com")
RUN_TEST(Blogger, "blogger.com")
RUN_TEST(Instagram, "instagram.com")
RUN_TEST(IGN, "ign.com")
RUN_TEST(AVG, "avg.com")
RUN_TEST(Groupon, "groupon.com")
RUN_TEST(CBSSports, "cbssports.com")
RUN_TEST(Reuters, "reuters.com")
RUN_TEST(TheFreeDictionary, "thefreedictionary.com")
RUN_TEST(SalesForce, "salesforce.com")
RUN_TEST(Southwest, "southwest.com")
RUN_TEST(Woot, "woot.com")
RUN_TEST(QQ, "qq.com")
RUN_TEST(TaoBao, "world.taobao.com")
RUN_TEST(TMall, "tmall.com")
RUN_TEST(Sohu, "sohu.com")
RUN_TEST(VK, "vk.com")
RUN_TEST(Sina, "sina.com.cn")
RUN_TEST(Weibo, "weibo.com")
RUN_TEST(Twitch, "twitch.tv")
RUN_TEST(WhatsApp, "whatsapp.com")
RUN_TEST(AliPay, "www.alipay.com")
RUN_TEST(Naver, "naver.com")
RUN_TEST(AliexPress, "aliexpress.com")
RUN_TEST(GitHub, "github.com")
RUN_TEST(Office, "office.com")
RUN_TEST(AmazonJapan, "www.amazon.co.jp")
RUN_TEST(Fandom, "fandom.com")
RUN_TEST(Imgur, "imgur.com")
RUN_TEST(Quora, "quora.com")
RUN_TEST(Roblox, "roblox.com")
RUN_TEST(AmazonAWS, "aws.amazon.com")
RUN_TEST(Chase, "chase.com")
RUN_TEST(Spotify, "spotify.com")
RUN_TEST(ESPN, "espn.com")
RUN_TEST(Discord, "discordapp.com")
RUN_TEST(Medium, "medium.com")
RUN_TEST(StackExchange, "stackexchange.com")
RUN_TEST(NIH, "nih.gov")
RUN_TEST(Indeed, "indeed.com")
RUN_TEST(ResearchGate, "researchgate.net")
RUN_TEST(Trello, "trello.com")
RUN_TEST(W3Schools, "www.w3schools.com")
RUN_TEST(TheGuardian, "theguardian.com")
RUN_TEST(Alibaba, "alibaba.com")
RUN_TEST(Shutterstock, "shutterstock.com")
RUN_TEST(DuckDuckGo, "duckduckgo.com")
RUN_TEST(Canva, "canva.com")
RUN_TEST(Slack, "slack.com")
RUN_TEST(DailyMotion, "dailymotion.com")
RUN_TEST(BankOfAmerica, "www.bankofamerica.com")
RUN_TEST(WellsFargo, "wellsfargo.com")
RUN_TEST(SteamCommunity, "steamcommunity.com")
RUN_TEST(SpeedTest, "www.speedtest.net")
RUN_TEST(Yelp, "www.yelp.com")
RUN_TEST(Gamepedia, "www.gamepedia.com")
RUN_TEST(Softonic, "en.softonic.com")
RUN_TEST(Vice, "vice.com")
RUN_TEST(WikiHow, "wikihow.com")
RUN_TEST(Scribd, "scribd.com")
RUN_TEST(Messenger, "messenger.com")
RUN_TEST(TripAdvisor, "tripadvisor.com")
RUN_TEST(Mozilla, "mozilla.org")
RUN_TEST(Archive, "archive.org")
RUN_TEST(AirBNB, "airbnb.com")
RUN_TEST(Gfycat, "gfycat.com")
RUN_TEST(DailyMail, "dailymail.co.uk")
RUN_TEST(Intuit, "intuit.com")
RUN_TEST(Shopify, "shopify.com")
RUN_TEST(HomeDepot, "homedepot.com")
RUN_TEST(Patreon, "patreon.com")
RUN_TEST(GoFundMe, "gofundme.com")
RUN_TEST(USPS, "usps.com")
RUN_TEST(Breitbart, "breitbart.com")
RUN_TEST(HP, "hp.com")
RUN_TEST(CapitalOne, "www.capitalone.com")

*/
































