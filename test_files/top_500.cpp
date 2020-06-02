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

// These were taken from 5000best.com

#define GOOGLE "www.google.com"
#define FACEBOOK "facebook.com"
#define YOUTUBE "youtube.com"
#define YAHOO "yahoo.com"
#define TWITTER "twitter.com"
#define AMAZON "amazon.com"
#define EBAY "ebay.com"
#define CNN "cnn.com"
#define LINKEDIN "linkedin.com"
#define PINTEREST "pinterest.com"
#define NYTIMES "nytimes.com"
#define WIKIPEDIA "wikipedia.org"
#define BING "bing.com"
#define APPLE "apple.com"
#define WEATHER "weather.com"
#define MSN "www.msn.com"
#define MICROSOFT "microsoft.com"
#define WORDPRESS "wordpress.com"
#define AOL "aol.com"
#define TUMBLR "tumblr.com"

#define HUFFPOST "huffingtonpost.com"
#define LIVE "live.com"
#define FLICKR "flickr.com"
#define ETSY "etsy.com"
#define PAYPAL "paypal.com"
#define IMDB "imdb.com"
#define BLOGSPOT "blogspot.com"
#define ASK "ask.com"
#define ABOUT "about.com"
#define REDDIT "reddit.com"
#define PANDORA "pandora.com"
#define BBC "bbc.co.uk"
#define NFL "nfl.com"
#define WALMART "walmart.com"
#define USATODAY "usatoday.com"
#define FOXNEWS "foxnews.com"
#define DROPBOX "dropbox.com"
#define NEWEGG "newegg.com"
#define CRAIGSLIST "craigslist.com"
#define SWAGBUCKS "swagbucks.com"

#define NBCNEWS "nbcnews.com"
#define HULU "hulu.com"
#define CNET "cnet.com"
#define EHOW "ehow.com"
#define COMO "como.com"
#define DEVIANTART "deviantart.com"
#define VIMEO "vimeo.com"
#define ADOBE "adobe.com"
#define WASHINGTONPOST "washingtonpost.com"
#define TARGET "target.com"
#define NBA "nba.com"
#define BESTBUY "bestbuy.com"
#define STUMBLEUPON "stumbleupon.com"
#define GIZMODO "gizmodo.com"
#define POLITICO "politico.com"
#define STACKOVERFLOW "stackoverflow.com"
#define WIRED "wired.com"
#define SOUNDCLOUD "soundcloud.com"
#define MEDIAFIRE "mediafire.com"
#define HOOTSUITE "hootsuite.com"

#define GODADDY "godaddy.com"
#define NETFLIX "netflix.com"
#define BLOGGER "blogger.com"
#define INSTAGRAM "instagram.com"


#define HTTPS_PORT "443"

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


// TODO: in the future, test the error strings as well

TEST_F(Top500WebsitesTest, Google) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(GOOGLE, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Facebook) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(FACEBOOK, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Youtube) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(YOUTUBE, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Yahoo) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(YAHOO, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Twitter) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(TWITTER, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Amazon) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(AMAZON, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Ebay) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(EBAY, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, cnn) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(CNN, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, LinkedIn) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(LINKEDIN, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Pinterest) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(PINTEREST, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, NYTimes) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(NYTIMES, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Wikipedia) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(WIKIPEDIA, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Bing) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(BING, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Apple) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(APPLE, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Weather) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(WEATHER, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, msn) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(MSN, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Microsoft) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(MICROSOFT, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Wordpress) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(WORDPRESS, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, aol) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(AOL, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Tumblr) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(TUMBLR, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, HuffingtonPost) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(HUFFPOST, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Live) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(LIVE, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Flickr) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(FLICKR, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Etsy) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(ETSY, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, PayPal) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(PAYPAL, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Imdb) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(IMDB, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Blogspot) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(BLOGSPOT, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Ask) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(ASK, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, About) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(ABOUT, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Reddit) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(REDDIT, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Pandora) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(PANDORA, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, bbc) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(BBC, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, nfl) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(NFL, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Walmart) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(WALMART, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, USAToday) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(USATODAY, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, FoxNews) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(FOXNEWS, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Dropbox) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(DROPBOX, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, NewEgg) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(NEWEGG, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Craigslist) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(CRAIGSLIST, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Swagbucks) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(SWAGBUCKS, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, NBCNews) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(NBCNEWS, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Hulu) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(HULU, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, CNet) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(CNET, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, eHow) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(EHOW, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Como) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(COMO, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, DeviantArt) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(DEVIANTART, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Vimeo) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(VIMEO, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Adobe) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(ADOBE, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, WashingtonPost) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(WASHINGTONPOST, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Target) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(TARGET, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, nba) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(NBA, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, BestBuy) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(BESTBUY, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, StumbleUpon) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(STUMBLEUPON, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Gizmodo) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(GIZMODO, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Politico) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(POLITICO, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, StackOverflow) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(STACKOVERFLOW, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Wired) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(WIRED, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, SoundCloud) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(SOUNDCLOUD, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, MediaFire) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(MEDIAFIRE, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}TEST_F(Top500WebsitesTest, HootSuite) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(HOOTSUITE, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, GoDaddy) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(GODADDY, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Netflix) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(NETFLIX, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Blogger) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(BLOGGER, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

TEST_F(Top500WebsitesTest, Instagram) {

    TEST_TIMEOUT_BEGIN

    result = run_http_client(INSTAGRAM, HTTPS_PORT, &resp, &resp_len);
    EXPECT_EQ(result, (int) E_SUCCESS);

    TEST_TIMEOUT_FAIL_END(TIMEOUT)
}

