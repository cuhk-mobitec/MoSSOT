# -*- coding: utf-8 -*-
import difflib
import json
import re
from time import sleep

from appium.webdriver.common.touch_action import TouchAction
from selenium.common.exceptions import NoSuchElementException, WebDriverException

import layout
from logger import logger
import helper
from emulator import ADB
import myexceptions


class SmartMonkey(object):
    def __init__(self, driver, package=None, app_style='chinese'):
        self.driver = driver
        self.package = package
        self.app_style = app_style
        self.action = TouchAction(driver)
        self.window_size = driver.get_window_size()
        self.loginkw = [u'login', u'sign in', u'log in', u'登录', u'signup', u'sign up', u'注册', u'facebook']
        self.skipkw = [u'skip', u'跳过', u'进入', u'close']
        self.avoidkw = [u'install', u'update', u'upgrade', u'download', u'rate',
                        u'(?<!后|不)安装', u'(?<!后|不)更新', u'(?<!后|不)升级', u'(?<!后|不)下载', u'应用市场',
                        u'(?<!后|不)分享', u'(?<!后|不)评价', u'(?<!后|不)开启', u'去设置']
        self.waited = False
        self.rec_count = 0
        self.SKIP_IRR_LIMIT = 20
        self.DFS_DEPTH_LIMIT = 3

    def skip_irrelevant(self, initial=True, limit=None, detect_login=None):
        """ Skip irrelevant activities and dialogs like update and permission notifications
            Will call itself recursively until no irrelevant things found

            This function may be invoked frequently to prevent stuck
        """
        if initial:
            self.rec_count = 0
        if detect_login is None:
            detect_login = self.app_style == 'international'
        if limit is None:
            if self.SKIP_IRR_LIMIT:
                limit = self.SKIP_IRR_LIMIT
            else:
                limit = 20

        elif self.rec_count >= self.SKIP_IRR_LIMIT:
            raise myexceptions.SkipIrrelevantExceedLimit
        else:
            self.rec_count += 1

        try:
            cur_act = self.driver.current_activity

            if not self.is_in_app():
                logger.error('!!! APP not running, raise exception ...')
                raise myexceptions.AppNotRunningException

            logger.debug(u"Try to check and skip irrelevant activities {1}, current activity: {0}"
                         .format(cur_act, "(%d)" % self.rec_count if self.rec_count else ""))
            clickable = self.driver.find_elements_by_android_uiautomator('new UiSelector().clickable(true)')
            textedit = self.driver.find_elements_by_class_name('android.widget.EditText')

            logger.verbose(u'''Found:
                        {0} clickable elements
                        {1} TextEdit elements'''.format(len(clickable), len(textedit)))

            # Nothing can be clicked, wait or swipe
            if len(clickable) == 0 \
                    and len(textedit) == 0:
                if not self.waited:
                    logger.debug(u'Seems to be in loading page, wait then try again ...')
                    timeout = 6
                    source_before = self.page_source
                    while timeout:
                        sleep(1)
                        source_after = self.page_source
                        if difflib.SequenceMatcher(None, source_before, source_after).ratio() < 0.8:
                            break
                        source_before = source_after
                        timeout -= 1
                    self.waited = 1
                elif self.waited == 1:
                    logger.debug(u'\ttap then wait ...')
                    self.driver.tap([(self.window_size['width'] / 2, self.window_size['height'] / 2)])
                    sleep(1)
                    self.waited = 2
                elif self.waited > 1:
                    logger.debug(u'\tswipe then wait ...')
                    self.swipe_left()
                    sleep(1)
                self.skip_irrelevant(initial=False, limit=limit, detect_login=detect_login)
                return

            # Welcome page
            skippable = self.contain_skip_text()
            get_sinks = lambda: self.driver.find_elements_by_xpath('//*[not(*)]')
            if not self.is_in_dialog() \
                    and ((skippable or (len(clickable) in range(1, 5) and len(textedit) == 0))
                         and len(get_sinks()) < 20):
                logger.debug(u'Seems to be in welcome page, try bypassing it')

                if detect_login and self.contain_login_text():
                    logger.debug(u'Find login keywords in welcome page, break skip_irrelevant')
                    return

                if skippable:
                    for kw in self.skipkw:
                        for e in self.find_elements_by_keyword(kw):
                            if self.tap_test(e, diff=0.98):
                                self.skip_irrelevant(initial=False, limit=limit, detect_login=detect_login)
                                return

                safe_clickable = self.find_safe_clickable_elements()
                if safe_clickable:
                    to_tap = safe_clickable[-1]
                    ele_info = layout.ElementInfo(to_tap)
                    logger.debug(u'Tapped {0}'.format(ele_info))
                    if not self.tap_test(to_tap, diff=0.98):
                        logger.warning(u'Tap failed: {0}, try swiping'.format(ele_info))
                        self.swipe_left()

                self.skip_irrelevant(initial=False, limit=limit, detect_login=detect_login)
                return

            # Dialog
            # TODO: decide cancel/ok by context
            if self.is_in_dialog() \
                    and len(clickable) in range(1, 5) \
                    and len(textedit) == 0:
                logger.debug(u'Seems to be a dialog, try bypassing it')

                if detect_login and self.contain_login_text():
                    logger.debug(u'Find login keywords in welcome page, break skip_irrelevant')
                    return

                safe_clickable = self.find_safe_clickable_elements()
                if not safe_clickable:
                    raise myexceptions.NoSafeClickableElement("Seems like a dialog that requiring update")
                source_before_tap = self.page_source
                to_tap = safe_clickable[-1]
                ele_info = layout.ElementInfo(to_tap)
                logger.debug(u'Tapped {0}'.format(ele_info))
                self.tap(to_tap)
                if self.driver.current_activity == cur_act \
                        and difflib.SequenceMatcher(None, self.page_source.lower(),
                                                    source_before_tap).ratio() > 0.95:
                    logger.warning(u'Tap failed: {0}'.format(ele_info))
                self.skip_irrelevant(initial=False, limit=limit, detect_login=detect_login)
                return

            # City list
            cities_pattern = u'(?:鞍山|安庆|安阳|安顺|北京|天津|上海|深圳|广州|成都|南京|重庆|杭州)市?'
            filtered = self.find_elements_by_keyword(cities_pattern, clickable_only=False, exact=True, scroll=False)
            if len(filtered) > 3:
                logger.debug(u'Seems to be a city select page, try bypassing it')
                to_tap = filtered[0]
                ele_info = layout.ElementInfo(to_tap)
                logger.debug(u'Tapped {0}'.format(ele_info))
                self.tap(to_tap)
                if self.driver.current_activity == cur_act:
                    logger.warning(u'Tap failed: {0}'.format(ele_info))
                self.skip_irrelevant(initial=False, limit=limit, detect_login=detect_login)
                return
        except NoSuchElementException:
            self.skip_irrelevant(initial=False, limit=limit, detect_login=detect_login)

    def is_in_dialog(self):
        # find_element_by_class_name sorts elements from child to ancestor (not sure),
        # while by_android_uiautomator sorts them from ancestor to child, but slower
        frame = self.driver.find_elements_by_class_name('android.widget.FrameLayout')[-1]
        window_area = self.window_size['width'] * self.window_size['height']
        frame_area = frame.size['width'] * frame.size['height']
        ratio = 1.0 * frame_area / window_area
        # common.debug('Current activity size ratio: {0}'.format(ratio))
        return ratio < 0.8

    def page_contain_keytext(self, keytext, mode='rough'):
        match = lambda s: any([re.search(kw, s, re.I) for kw in keytext])
        if mode == 'rough':
            source = self.page_source
            return match(source)
        elif mode == 'sinks_only':
            elements = self.driver.find_elements_by_xpath("//*[not(*)]")
        elif mode == 'clickable_sinks':
            elements = self.driver.find_elements_by_xpath("//*[not(*) and @clickable='true']")
        else:
            elements = self.driver.find_elements_by_xpath('//*')
        text = [e.text for e in elements]
        return filter(match, text)

    def contain_login_text(self, keytext=None):
        if not keytext:
            keytext = self.loginkw
        return self.page_contain_keytext(keytext, mode='rough')

    def contain_skip_text(self, keytext=None):
        if not keytext:
            keytext = self.skipkw
        return self.page_contain_keytext(keytext, mode='rough')

    def find_elements_by_keyword(self, keyword, clickable_only=False, exact=False, scroll=False,
                                 text_max_len=0, sort_elements=False, use_uiautomator=True):
        """
        Find elements where keyword matches one of {text, resource id, content description}
        :param keyword: The keyword to search for
        :param clickable_only: Only return clickable elements if set to True
        :param exact: When exact is True, return only the whole word match. Otherwise return partial match as well.
        :param scroll: Scroll and search or only search current screen
        :param text_max_len: Limit maximum text length of returned elements
        :param sort_elements: Sort returned elements by text length. The shorter, the higher priority.
        :param use_uiautomator: Whether use UIAutomator or use pure xpath for element searching.
                                UIAutomator mode support regex, but cannot match other attributes like bounds.
                                Pure XPath mode doesn't support regex, but will match all attributes.
                                Also Pure XPath mode is supposed to be faster
                                    as it sends 1 request per search while UIAutomator mode sends 3.
        :return: list of element objects
        """

        # TODO: make sure no path config use these keywords anymore and remove this deprecated part
        # =========================================================
        xmax = self.window_size['width']
        ymax = self.window_size['height']
        corner_words = {
            'TOP_LEFT_CORNER': [0, 200, 0, 200],
            'TOP_RIGHT_CORNER': [xmax - 200, xmax, 0, 200],
            'BOTTOM_RIGHT_CORNER': [xmax - 200, xmax, ymax - 200, ymax],
            'BOTTOM_LEFT_CORNER': [0, 200, ymax - 200, ymax]
        }
        if keyword in corner_words:
            return self.find_clickable_elements_in_area(*corner_words[keyword])

        # ==========================================================
        # =================== Use UIAutomator ======================
        # ==========================================================
        if use_uiautomator:
            if exact:
                regex = u"(?i)^\\s*(?:{0})\\s*$".format(keyword)
            else:
                regex = u"(?i).*(?:{0}).*".format(keyword)
            queries = [
                u'new UiSelector().textMatches("{0}")'.format(regex),
                u'new UiSelector().resourceIdMatches("{0}")'.format(regex),
                u'new UiSelector().descriptionMatches("{0}")'.format(regex)
            ]
            if clickable_only:
                queries = [q + u'.clickable(true)' for q in queries]

            # TODO: find a way to search all three attributes in one scroll
            # https://android.googlesource.com/platform/frameworks/testing/+/master/uiautomator/library/core-src/com/android/uiautomator/core/UiScrollable.java
            if scroll:
                queries = [u'new UiScrollable(new UiSelector().scrollable(true))'
                           u'.setMaxSearchSwipes(3).scrollIntoView({0})'.format(q) for q in queries]
                elements = []
                for q in queries:
                    elements = self.driver.find_elements_by_android_uiautomator(q)
                    # short cut in scroll mode (once found, return) to prevent too many times of scrolling.
                    if elements:
                        break
            else:
                q_combined = ';'.join(queries)
                elements = self.driver.find_elements_by_android_uiautomator(q_combined)

        # ==========================================================
        # ======================= Use XPath ========================
        # ==========================================================

        # We can use one query to search for text and all attributes:
        # //*[text()[contains(,'keyword')] or @*[contains(.,'keyword')]]
        # Use translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') for case-insensitive in XPath1.0
        #
        # !!! Appium doesnt support XPath2.0, thus doesnt support matches() and lower-case()
        # Case-insensitive:
        # //*[text()[matches(.,'keyword','i')] or @*[matches(.,'keyword','i')]]
        # Clickable only:
        # //*[text()[matches(.,'keyword','i')] or @*[matches(.,'keyword','i')] and @clickable='true']

        else:
            keyword = keyword.lower()
            if exact:
                condition = u"{1}='{0}'" \
                    .format(keyword, "translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')")
            else:
                condition = u"contains({1},'{0}')" \
                    .format(keyword, "translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')")

            if clickable_only:
                query = u"//*[text()[{0}] or @*[{0}] and @clickable='true']".format(condition)
            else:
                query = u"//*[text()[{0}] or @*[{0}]]".format(condition)

            elements = self.driver.find_elements_by_xpath(query)
            if scroll:
                scrollables = self.driver.find_elements_by_xpath(u"//*[@scrollable='true']")
                if scrollables:
                    scroll_cnt = 0
                    while not elements and scroll_cnt < 3:
                        areas = [s.size['width'] * s.size['height'] for s in scrollables]
                        i_max = areas.index(max(areas))
                        to_scroll = scrollables[i_max]
                        x = to_scroll.location['x'] + to_scroll.size['width'] / 2
                        self.scroll_down(x=x)
                        scroll_cnt += 1
                        elements = self.driver.find_elements_by_xpath(query)

        # ==========================================================
        # ===================== sort elements ======================
        # ==========================================================
        if text_max_len or sort_elements:
            len_elements = [(len(layout.ElementInfo(e).text)
                             if layout.ElementInfo(e).text
                             else len(layout.ElementInfo(e).desc), e)
                            for e in elements]  # if elements have no texts, try content_desc
            if text_max_len:
                len_elements = [pair for pair in len_elements if pair[0] <= text_max_len]
            if sort_elements:
                len_elements.sort()
            elements = [e for (l, e) in len_elements]
            if elements:
                logger.verbose(u"max: {0}, sort: {1} - {2}".format(text_max_len, sort_elements,
                                                                   [p[0] for p in len_elements]))

        return elements

    def find_clickable_elements_in_area(self, x1, x2, y1, y2):
        if x1 > x2 or y1 > y2:
            logger.warning(u'Invalid area to find elements')
            return None
        if x2 > self.window_size['width'] or y2 > self.window_size['height']:
            logger.warning(u'Area to find elements is out of screen')
            return None
        clickable = self.driver.find_elements_by_android_uiautomator('new UiSelector().clickable(true)')
        elements = []
        for e in clickable:
            if x1 <= e.location['x'] <= x2 and y1 <= e.location['y'] <= y2:
                elements.append(e)
        return elements

    def find_safe_clickable_elements(self, blacklist=None):
        if blacklist is None:
            blacklist = self.avoidkw
        clickable = self.driver.find_elements_by_android_uiautomator('new UiSelector().clickable(true)')
        filtered = [e for e in clickable
                    if not any([re.search(kw, e.get_attribute('text').lower()) for kw in blacklist])]
        return filtered

    def is_in_app(self, retry_flag=False):
        if not self.package:
            logger.debug(u"Package not specified, skip in-app check")
            return True
        blacklist = ['com', 'android', 'view', 'ui']
        # check for keyword match apart from common package word
        if 'udid' in self.driver.desired_capabilities and self.driver.desired_capabilities['udid']:
            adb = ADB(serial=self.driver.desired_capabilities['udid'])
        else:
            adb = ADB()
        common_word = set(adb.current_package().lower().split('.')) \
            .intersection(self.package.lower().split('.'))
        is_related = len(set(blacklist).union(common_word) - set(blacklist)) > 0
        # Sometimes driver.current_activity returns None
        current_activity = self.driver.current_activity if self.driver.current_activity else 'None'
        is_permission_dialog = '.permission.ui.GrantPermissionsActivity' in current_activity
        is_idp = any([act in current_activity for act in ['SSOAuthorizeActivity', 'OAuth_UI', 'FacebookActivity']])
        if is_related or is_permission_dialog or is_idp:
            return True
        else:
            if retry_flag:
                return False
            self.driver.back()
            return self.is_in_app(retry_flag=True)

    def scroll_down(self, swipe=1, x=None):
        for i in range(swipe):
            if x:
                start_x = end_x = x
            else:
                start_x = end_x = self.window_size['width'] / 2
            start_y = self.window_size['height'] * 0.8
            end_y = self.window_size['height'] * 0.2
            try:
                self.driver.swipe(start_x, start_y, end_x, end_y)
            except WebDriverException:
                logger.warning('Swipe action exception')
            sleep(1)

    def scroll_up(self, swipe=1, x=None):
        for i in range(swipe):
            if x:
                start_x = end_x = x
            else:
                start_x = end_x = self.window_size['width'] / 2
            start_y = self.window_size['height'] * 0.2
            end_y = self.window_size['height'] * 0.8
            try:
                self.driver.swipe(start_x, start_y, end_x, end_y)
            except WebDriverException:
                logger.warning('Swipe action exception')
            sleep(1)

    def swipe_left(self):
        start_x = self.window_size['width'] - 100
        end_x = 100
        start_y = end_y = self.window_size['height'] / 2
        try:
            self.driver.swipe(start_x, start_y, end_x, end_y)
        except WebDriverException:
            logger.warning('Swipe action exception, ignored')

    def tap(self, element=None, x=None, y=None):
        self.action.tap(element, x, y).perform()

    def tap_test(self, element=None, x=None, y=None, diff=0.98):
        if self.__class__.__name__ == 'Navigator':
            diff = 1
        act_before = self.driver.current_activity
        source_before = self.page_source.lower()

        self.action.tap(element, x, y).perform()
        diff_ratio = difflib.SequenceMatcher(None, self.page_source.lower(), source_before).ratio()
        act_after = self.driver.current_activity
        logger.verbose(u'Before tap: {}. After tap: {}. Diff: {}'.format(act_before, act_after, diff_ratio))
        if act_after == act_before \
                and diff_ratio > diff:
            return False
        else:
            return True

    def tap_xpath(self, query, siblings_on=True):
        try:
            tap_suc = False
            logger.debug(u'Try to click by xpath {0}'.format(query))

            elements = self.driver.find_elements_by_xpath(query)
            if not elements:
                logger.debug(u'\tTry scroll and search')
                self.scroll_down(swipe=3)
                elements = self.driver.find_elements_by_xpath(query)
                cnt = 0
                while not elements and cnt < 3:
                    self.scroll_up()
                    elements = self.driver.find_elements_by_xpath(query)
                    cnt = cnt + 1
            logger.debug(u'\tFind {0} elements'.format(len(elements)))

            if not elements:
                logger.error(u'\tXpath query {0} failed'.format(query))
                return False
            for e in elements:
                tap_suc = self.tap_test(e)
                if tap_suc:
                    break
                else:
                    if siblings_on and not e.get_attribute('clickable') == 'true':
                        logger.debug(u'\t\tTap failed, try siblings')
                        tap_suc = self.tap_siblings(e)
                        if tap_suc:
                            break
                    logger.debug(u'\tTap failed, try other matches')
            if not tap_suc:
                logger.error(u'Click by xpath "{0}" unsuccessful by all means'.format(query))
            return tap_suc

        except NoSuchElementException:
            self.skip_irrelevant()
            return self.tap_xpath(query, siblings_on=siblings_on)

    def tap_keyword(self, keyword, siblings_on=True, retry=3):
        try:
            tap_suc = False
            logger.debug(u'Try to click by keyword {0}'.format(keyword))

            # Quick try
            elements = self.find_elements_by_keyword(keyword, clickable_only=False, exact=True)
            logger.debug(u'\tQuick try, find {0} elements'.format(len(elements)))
            for e in elements:
                if self.tap_test(e):
                    return True

            # Comprehensive Try
            logger.debug(u'\tComprehensive try')
            elements = self.find_elements_by_keyword(keyword, clickable_only=False,
                                                     sort_elements=True, text_max_len=32)
            if not elements:
                logger.debug(u'\tTry scroll')
                elements = self.find_elements_by_keyword(keyword, clickable_only=False, scroll=True,
                                                         sort_elements=True, text_max_len=32)
                if not elements:
                    logger.error(u'\tCannot find keyword "{0}"'.format(keyword))
                    return False
            for e in elements:
                logger.debug(u'\tTry tapping: {0}'.format(layout.ElementInfo(e)))
                tap_suc = self.tap_test(e)
                if tap_suc:
                    break
                else:
                    if siblings_on and not e.get_attribute('clickable') == 'true':
                        logger.debug(u'\t\tTap failed, try siblings')
                        tap_suc = self.tap_siblings(e)
                        if tap_suc:
                            break
                    logger.debug(u'\tTap failed, try other matches')
            if not tap_suc:
                logger.error(u'Click by keyword "{0}" unsuccessful by all means'.format(keyword))
            return tap_suc
        except NoSuchElementException:
            if retry > 0:
                retry = retry - 1
                self.skip_irrelevant()
                return self.tap_keyword(keyword, siblings_on=siblings_on, retry=retry)

    def tap_siblings(self, e):
        siblings = self.find_clickable_siblings(e)
        logger.debug(u'\t\tFind {} clickable siblings'.format(len(siblings)))
        tap_suc = False
        for s in siblings:
            ele_info = layout.ElementInfo(s)
            tap_suc = self.tap_test(s)
            if tap_suc:
                logger.debug(u'\t\tSibling click successful on {0}'.format(ele_info))
                break
        return tap_suc

    def find_clickable_siblings(self, e):
        info = layout.ElementInfo(e)
        if info.bounds():
            # common.debug(u'\t\tFind sibling by bounds: {}'.format(info.bounds))
            query = u"//*[@bounds='{0}']/following-sibling::*[@clickable='true']" \
                    u"| //*[@bounds='{0}']/preceding-sibling::*[@clickable='true']".format(info.bounds)
        elif info.res_id:
            # common.debug(u'\t\tFind sibling by res_id: {}'.format(info.res_id))
            query = u"//*[@resource-id='{0}']/following-sibling::*[@clickable='true']" \
                    u"| //*[@resource-id='{0}']/preceding-sibling::*[@clickable='true']".format(info.res_id)
        elif info.text:
            # common.debug(u'\t\tFind sibling by text: {}'.format(info.text))
            query = u"//*[@text='{0}']/following-sibling::*[@clickable='true']" \
                    u"| //*[@text='{0}']/preceding-sibling::*[@clickable='true']" \
                    u"| //*[text()='{0}']/following-sibling::*[@clickable='true']" \
                    u"| //*[text()='{0}']/preceding-sibling::*[@clickable='true']".format(info.text)
        elif info.desc():
            # common.debug(u'\t\tFind sibling by content_desc: {}'.format(info.desc))
            query = u"//*[@content-desc='{0}']/following-sibling::*[@clickable='true']" \
                    u"| //*[@content-desc='{0}']/preceding-sibling::*[@clickable='true']".format(info.desc)
        else:
            return []
        elements = self.driver.find_elements_by_xpath(query)
        if elements:
            return elements
        else:
            return []

    def wait_for_keyword(self, keyword, timeout=10):
        t = timeout
        result = None
        while t > 0:
            try:
                result = re.search(keyword, self.page_source, re.I)
            except WebDriverException:
                pass
            if result:
                return True
            sleep(1)
            t -= 1
        return False

    def wait_for_keyword2(self, keyword, timeout=10):
        t = timeout
        result = None
        while t > 0:
            try:
                result = re.search(keyword, self.page_source, re.I)
            except WebDriverException:
                pass
            if result:
                return result.group()
            sleep(1)
            t -= 1
        return False

    def wait_for_activities(self, activities, timeout=10):
        t = timeout
        while t > 0:
            cur_act = self.driver.current_activity
            if cur_act in activities:
                return cur_act
            else:
                sleep(1)
                t -= 1
        return False

    def wait_for_destination(self, destination, timeout=10):
        # Multiple destinations, check all keywords
        if isinstance(destination, dict):
            t = timeout
            while t > 0:
                for (k, v) in destination.items():
                    if re.search(v, self.page_source, re.I):
                        return k
                    else:
                        sleep(1)
                        t -= 1
            return False
        if isinstance(destination, list):
            t = timeout
            while t > 0:
                for kw in destination:
                    if re.search(kw, self.page_source, re.I):
                        return True
                    else:
                        sleep(1)
                        t -= 1
            return False
        # Single destination, fall back to wait_for_keyword
        else:
            return self.wait_for_keyword(destination, timeout=timeout)

    def better_start_activity(self, activity, retry=5):
        """ Overwrite default Appium's start_activity with hard-coded 10 retries
            return True if started activity and package match, return False otherwise
        """
        assert retry > 0
        if self.package:
            package = self.package
        else:
            if 'appPackage' in self.driver.desired_capabilities:
                package = self.driver.desired_capabilities['appPackage']
                logger.warning(u"package unspecified, use driver's default: {}".format(package))
            else:
                raise Exception("package not specified")

        logger.debug(u'Try to launch activity %s', activity)
        for _ in range(5):
            try:
                self.driver.start_activity(package, activity, app_wait_activity='*', app_wait_package=package)
                break
            except WebDriverException as e:
                logger.error(e)
                sleep(1)
        else:
            raise myexceptions.TestInitException('Fail to launch activity {} for package {}'\
                    .format(activity, package))

        for i in xrange(retry):
            current_activity = self.driver.current_activity
            if current_activity == activity:
                return True
            logger.debug(u'\tIncorrect package and activity. Retrying (%d)' % (i + 1))
            sleep(1)
        logger.debug(u'Use current activity %s', current_activity)
        return False

        # TODO: implement scroll()/scrollToEnd() using driver.swipe() and top element difference
    @property
    def page_source(self):
        """wrapper around appium page_source to catch exception"""
        source = None
        e = None
        for _ in range(3):
            try:
                source = self.driver.page_source
                if source:
                    break
            except WebDriverException as e:
                sleep(1)
                continue
        else:
            raise WebDriverException(e)
        return source


class Explorer(SmartMonkey):
    def __init__(self, driver, package=None, app_style='chinese', scan_keywords=None, dfs_config=None,
                 dest_keywords=None, dest_activities=None):
        super(Explorer, self).__init__(driver, package=package, app_style=app_style)
        self._home_activity = None
        self._scan_keywords = None
        self._dfs_config = None
        self._dest_keywords = None
        self._dest_activities = None
        if scan_keywords:
            self.set_scan_keywords(scan_keywords)
        if dfs_config:
            self.set_dfs_config(dfs_config)
        if dest_keywords:
            self.set_dest_keywords(dest_keywords)
        if dest_activities:
            self.set_dest_activities(dest_activities)
        self.visited_elements = []
        self.visiting_elements = []

    def set_home_activity(self, home_activity):
        self._home_activity = home_activity

    def set_scan_keywords(self, scan_keywords):
        if isinstance(scan_keywords[0], list):
            self._scan_keywords = scan_keywords
        else:
            raise Exception('[Explorer] cannot set path_keyword: not in 2D list format')

    def set_dfs_config(self, dfs_config):
        # TODO: finish this
        if isinstance(dfs_config[0], dict):
            self._dfs_config = dfs_config
        else:
            raise Exception('[Explorer] cannot set keyword: not in list-of-dict format')

    def set_dest_keywords(self, dest_keywords):
        self._dest_keywords = dest_keywords

    def set_dest_activities(self, dest_activities):
        self._dest_activities = dest_activities

    def return_to_home(self):
        if not self._home_activity:
            raise Exception('home_activity not defined, cannot return to home')
        self.better_start_activity(self._home_activity)
        self.skip_irrelevant()

    def explore(self, result_type='attribute', algorithm='scan'):
        """ Execute exploration

        :param result_type: attribute - result keywords are matched attribute of elements.
                            pattern - result keywords are matched patterns defined in conf file.
        :param algorithm: scan - level-based keywords scan
                          dfs - DFS search
        :return: matched keyword list, or error message
        """
        if algorithm == 'scan':
            # only modify local variable copy
            path_kw = self._scan_keywords
            result = self._scan_attempt(path_kw, result_path=None, last_matched=None, result_type=result_type)
            cnt = 0
            while result['status'] == 'deadend':
                cnt += 1
                # remove last matched keyword from path_kw
                last = result['last_turn']
                path_kw[last['lv']].remove(last['kw'])
                # restart exploration from root
                logger.info(u"Deadend, returning home ({}). Path: ->{}".format(cnt, u'->'.join(result['path'])))
                self.return_to_home()
                result = self._scan_attempt(path_kw, result_path=None, last_matched=None, result_type=result_type)
            return result

        elif algorithm == 'dfs':
            result = self._dfs(0)
            logger.info(result)

        else:
            raise Exception('No such exploration algorithm: %s' % algorithm)

    def _dfs(self, depth):
        logger.debug('Into DFS depth {}'.format(depth))
        # Found destination
        path = [e.info for e in self.visiting_elements]
        if self._dest_keywords and self.wait_for_destination(self._dest_keywords, timeout=10):
            logger.info(u'Destination keywords matched')
            return {'status': 'success', 'path': path, 'package': self.package}
        if self._dest_activities and self.wait_for_activities(self._dest_activities, timeout=10):
            logger.info(u'Destination activities matched.')
            return {'status': 'success', 'path': path, 'package': self.package}

        # Reach depth limit
        if depth == self.DFS_DEPTH_LIMIT:
            logger.debug('Reached DFS depth limit: {}'.format(self.DFS_DEPTH_LIMIT))
            self.visited_elements.append(self.visiting_elements.pop())
            self.return_to_home()
            return self._dfs(0)

        # Find next unvisited element in current page
        for ue in self._elements_generator(by_xml=True, score_threshold=0.15):
            status = 'untouched'
            # detect if exploration of ue is on going
            for ve in self.visiting_elements:
                if ue.diff(ve) < 0.05:
                    logger.verbose(u'{} is still under visit'.format(ue.info))
                    status = 'revisit'
                    break
            # detect if
            if status == 'untouched':
                for ve in self.visited_elements:
                    if ue.diff(ve) < 0.05:
                        logger.verbose(u'{} has been visited'.format(ue.info))
                        status = 'visited'
                        break
            if not status == 'visited':
                logger.debug(u'DFS: try visiting {}'.format(ue.info))
                if self.tap_test(ue.get_web_element(driver=self.driver)):
                    if not status == 'revisit':
                        self.visiting_elements.append(ue)
                    return self._dfs(depth+1)
                else:
                    self.visited_elements.append(ue)

        # All elements in current page have been tried
        # If in root page, exploration is done
        if depth == 0:
            logger.info('All explored but found nothing')
            return {'status': 'failed', 'path': None, 'package': self.package}
        # TODO: jump back to parent page
        # If in child page, return to root page and continue exploration
        else:
            self.visited_elements.append(self.visiting_elements.pop())
            self.return_to_home()
            return self._dfs(0)

    def _elements_generator(self, by_xml=True, score_threshold=0.0):
        """
        Elements generator to generate next element for Explorer in an activity
        :param by_xml: If True, parse elements from static XML.
                       Otherwise get elements one by one through UIAutomator (extremely slow).
        :return: An element generator
        """
        if by_xml:
            activity = self.driver.current_activity
            xml = self.page_source.encode('utf-8')
            # TODO: this looks slow, could defer it to diff()
            img = self.driver.get_screenshot_as_png()

            page = layout.UniquePage(xml, activity, screen_img_data=img)
            all_ue = list(page.get_all_elements())

        else:
            all_ue = []
            for e in self.driver.find_elements_by_android_uiautomator('new UiSelector().clickable(true)'):
                all_ue.append(layout.UniqueElement(e))

        # filter by threshold
        all_ue = [u for u in all_ue if u.score > score_threshold]
        # sort by score
        sorted_ue = sorted(all_ue, key=lambda u: u.score, reverse=True)
        for ue in sorted_ue:
            yield ue

    def _scan_attempt(self, path_keywords, result_path=None, last_matched=None, result_type='attribute', retry=0):
        """One scan attempt for exploration by level-based keywords scan

        :param path_keywords: 2-D keyword list, do recursive fuzzy match
        :param result_path: list storing deterministic result path
        :param last_matched: record last matched keywords, if explore failed, remove it from path_keywords
        :param result_type: attribute - result keywords are matched attribute of elements.
                            pattern - result keywords are matched patterns defined in conf file.
        :param retry: retry flag for scrolling search
        :return: matched keyword list, or error message
        """

        # fix "default parameter is mutable" warning
        if result_path is None:
            result_path = []

        # Return condition: Every level of path_keywords is exhausted - level 0 DOES match
        #                   If dest_keywords is defined, double check for destination match
        if not path_keywords:
            if self._dest_keywords or self._dest_activities:
                if self._dest_keywords and self.wait_for_destination(self._dest_keywords, timeout=10):
                    logger.info(u'Destination keywords matched. Path: ->%s' % u'->'.join(result_path))
                    return {'status': 'success', 'path': result_path, 'package': self.package}
                elif self._dest_activities and self.wait_for_activities(self._dest_activities, timeout=10):
                    logger.info(u'Destination activities matched. Path: ->%s' % u'->'.join(result_path))
                    return {'status': 'success', 'path': result_path, 'package': self.package}
                else:
                    logger.debug('Level 0 matched, but wrong destination')
                    return {'status': 'deadend', 'last_turn': last_matched, 'path': result_path,
                            'package': self.package}
            else:
                logger.info('Level 0 keywords matched')
                return {'status': 'success', 'path': result_path, 'package': self.package}

        # 2D list: fuzzy keyword path
        level = 0
        for kwline in path_keywords:
            # self.skip_irrelevant()
            logger.debug(u'Try level {0} keywords'.format(level))
            for kw in kwline:
                elements = self.find_elements_by_keyword(kw, clickable_only=False, exact=False,
                                                         text_max_len=32, sort_elements=True)
                if elements:
                    logger.debug(u'\tMatched {0} elements'.format(len(elements)))
                    for e in elements:
                        e_info = layout.ElementInfo(e)
                        e_location = e.location
                        logger.debug(u'\t\tTap element {0}'.format(e_info))
                        if not self.tap_test(e):
                            logger.warning(u'\t\tTap failed, try next element')
                            continue
                        else:
                            last_matched = {'lv': level, 'kw': kw}
                            if result_type == 'attribute':
                                # Use matched element attribute as keyword
                                for s in [e_info.text, e_info.res_id, e_info.desc]:
                                    if re.search(kw, s, re.I):
                                        kw = s
                            logger.info(
                                u'Level {0} matched\n\tKeyword: {1}, Position: {2}'.format(level, kw, e_location))
                            result_path.append(kw)
                            # Recursion: with path_keywords level 0 - current level
                            return self._scan_attempt(path_keywords[:level], result_path=result_path,
                                                      last_matched=last_matched, result_type=result_type)
            level += 1

        # Tried all remaining levels, none matching

        # scroll to end and retry
        if retry == 0:
            # very naive scrolling
            logger.debug(u'\tNothing found, try scrolling to end ...')
            self.scroll_down(swipe=3)
            return self._scan_attempt(path_keywords, result_path=result_path,
                                      last_matched=last_matched, result_type=result_type, retry=1)
        # scrolled and retried, return result
        else:
            if last_matched is None:
                return {'status': 'failed', 'path': result_path, 'package': self.package}
            else:
                return {'status': 'deadend', 'last_turn': last_matched, 'path': result_path, 'package': self.package}


class Navigator(SmartMonkey):
    def __init__(self, driver, package=None, app_style='chinese', path=""):
        super(Navigator, self).__init__(driver, package=package, app_style=app_style)
        self.path = {}
        if path:
            self.update_path(path)

    def update_path(self, path):
        try:
            path = json.loads(path)
            stops = path['stops']
        except ValueError:
            logger.warning(u'Invalid path format')
            raise
        self.path = path

    def load_path(self, filename):
        try:
            with open(filename, 'r') as f:
                self.update_path(f.read())
                logger.debug(u'Path loaded from {}'.format(filename))
        except EnvironmentError:
            logger.error(u'Read file error: {}'.format(filename))

    # TODO: wait for next elements
    def navigate(self):
        stops = self.path['stops']
        step = len(stops)
        if 'destination' in self.path:
            destination = self.path['destination']
        else:
            destination = None

        for i in range(step):
            stop = stops[i]
            if 'optional' in stop and stop['optional']:
                # Optional keyword skipped if current keyword not found but next does
                if not re.search(stop['keyword'], self.page_source, re.I):
                    if i + 1 == step \
                            or (i + 1 < step and 'xpath' in stops[i + 1]) \
                            or (i + 1 < step and re.search(stops[i + 1]['keyword'], self.page_source, re.I)):
                        logger.debug(u'Optional keyword {} skipped'.format(stop['keyword']))
                        continue
            if 'xpath' in stop and stop['xpath']:
                tap_suc = self.tap_xpath(stop['xpath'])
            else:
                tap_suc = self.tap_keyword(stop['keyword'])
            if not tap_suc:
                self.skip_irrelevant()
                if 'xpath' in stop and stop['xpath']:
                    tap_suc = self.tap_xpath(stop['xpath'])
                else:
                    tap_suc = self.tap_keyword(stop['keyword'])
                if not tap_suc:
                    logger.error(u'Unable to continue navigation')
                    return False

        if destination is None:
            logger.info(u'[>] Destination undefined, sleep 5 seconds')
            sleep(5)
            return 'Uncertain'
        else:
            result = self.wait_for_destination(destination, timeout=20)
            if not result:
                self.skip_irrelevant()
                result = self.wait_for_destination(destination, timeout=10)
            if result:
                logger.info(u'[>] Destination reached')
                return result
            else:
                logger.error(u'Unable to reach destination')
                return False


class Stabilizer(SmartMonkey):
    def __init__(self, driver, package=None, app_style='chinese'):
        super(Stabilizer, self).__init__(driver, package=package, app_style=app_style)
        self.home_activity = None

    def get_home_activity(self):
        self.stabilize()
        self.home_activity = self.driver.current_activity
        return self.home_activity

    def stabilize(self, limit=None):
        return self.skip_irrelevant(limit=limit)

    def land_on_activity(self, activity):
        self.better_start_activity(activity)
        self.stabilize()

    def land_home(self):
        if not self.home_activity:
            logger.warning(u'land_home(): home_activity undefined, launch app instead')
            self.driver.launch_app()
            self.stabilize()
        self.land_on_activity(self.home_activity)
