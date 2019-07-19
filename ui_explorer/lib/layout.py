# -*- coding: utf-8 -*-
import re
from io import BytesIO
from functools import reduce
import operator

import imagehash
from PIL import Image
from lxml import etree
from selenium.common.exceptions import NoSuchElementException

from logger import logger
# logger.setLevel(5)

WEIGHTS = None

class UniquePage(object):
    """
    Rich object storing the an app page.
        A single activity can contain different pages.
    """
    def __init__(self, page_source, activity_name, screen_img_data=None):
        self._source = page_source
        self._activity = activity_name
        if screen_img_data:
            self.screen_im = Image.open(BytesIO(screen_img_data)).convert('RGB')
        root = etree.XML(self._source)
        self._tree = etree.ElementTree(root)
        self._clickable_area = []
        self._clickable_area_finalized = False

    def get_all_elements(self):
        """
        Get a generator of UniqueElement instance of all the elements on page
        :return: A generator of UniqueElement instances
        """
        for e in self._tree.iterfind("//*"):
            se = StaticElement(e, self)
            yield UniqueElement(se)

    def get_xpath(self, element):
        """
        Get absolute XPath for a given element
        :param element: a lxml.etree._Element instance
        :return: XPath expression string
        """
        return self._tree.getpath(element)

    def get_xpath_lite(self, element):
        """
        Get compressed XPath for a given element
        :param element: a lxml.etree._Element instance
        :return: XPath expression string
        """

    def validate_xpath(self, xpath):
        """
        Validate the XPath can locate element and it's unique
        :param xpath: XPath expression string
        :return: True / False
        """
        if len(self._tree.xpath(xpath)) == 1:
            return True
        else:
            return False

    @staticmethod
    def _is_inside(box1, box2):
        """
        Return True if box1 lays inside box2.
        :param element: a box is defined in the form of ((x1,y1),(x2,y2))
        :return: box1 inside box2 -> 1, box2 inside box1 -> -1, intersect -> 0
        """
        if box1[0][0] >= box2[0][0] and box1[0][1] >= box2[0][1] \
            and box1[1][0] <= box2[1][0] and box1[1][1] <= box2[1][1]:
            return 1
        elif box1[0][0] < box2[0][0] and box1[0][1] < box2[0][1] \
            and box1[1][0] > box2[1][0] and box1[1][1] > box2[1][1]:
            return -1
        else:
            return 0

    def _join_clickable_area(self, box):
        """
        Check through each marked box against the new box to generate a joint result
        """
        joint = []
        has_container = False 
        for marked in self._clickable_area:
            r = self._is_inside(box, marked)
            # keep marked area
            if r >= 0:
                joint.append(marked)
                # new box can be contained in some marked box
                if r > 0:
                    has_container = True
        # no marked box can contain the new box
        if not has_container:
            joint.append(box)
        self._clickable_area = joint

    def _mark_all_clickable_area(self):
        """
        Go through all elements to mark all clickable area in page at once.
        """
        for e in self._tree.iterfind("//*"):
            info = ElementInfo(StaticElement(e, self))
            if info.clickable:
                self._join_clickable_area(info.bounds)
        self._clickable_area_finalized = True

    def in_clickable_area(self, element):
        """
        Check whether the given element is in clickable area.
        This will recursively check the clickable attribute and bounds of its parent nodes
        :param element: a lxml.etree._Element instance
        :return: True or False
        """
        # the recursion has reached root of the tree
        if element is None or not element.get('class'):
            return False

        info = ElementInfo(StaticElement(element, self))

        # Check through area that already marked clickable
        bounds = info.bounds
        for box in self._clickable_area:
            if self._is_inside(bounds, box) > 0:
                return True

        if self._clickable_area_finalized:
            return False

        if info.clickable:
            self._join_clickable_area(info.bounds)
            return True

        # Recursively trace back to parent nodes. 
        # May not be used as its faster to mark all at the begining, therefore not tested.
        return self.in_clickable_area(element.getparent())


    @property
    def id(self):
        return self._activity


class StaticElement(object):
    """
    Static element composed of XML element object, belonging activity name and xpath
    """
    def __init__(self, element, page):
        self.element = element
        self.page = page


class UniqueElement(object):
    """
    Rich object storing elements information for identification and prioritizing.
        Properties need expensive computation (e.g. image hash) won't be available on initialization.
        The input element can be either a WebElement or a StaticElement.
    """
    def __init__(self, element):
        self._info = ElementInfo(element)
        self._element = element
        self._img_hash = None
        self._screenshot = None
        self._xpath = None
        self._score = 0
        self._config = WEIGHTS

        element_class = element.__class__.__name__

        # parse ElementNode from selenium element object
        if element_class == 'WebElement':
            self._static = False
            self._page = UniquePage(element.parent.page_source, element.parent.current_activity)
            size = element.parent.get_window_size()
            self._screen_size = (size['width'], size['height'])

        elif element_class == 'StaticElement':
            self._static = True
            self._page = element.page
            self._screen_im = element.page.screen_im
            self._screen_size = self._screen_im.size

        else:
            raise Exception("Cannot parse %s to ElementNode" % element)

    @property
    def info(self):
        return self._info

    @property
    def page(self):
        return self._page

    @property
    def img_hash(self):
        """ Calculate image hash of the element. Called only when other identifiers failed """
        if self._img_hash:
            return self._img_hash
        im = self.screenshot
        self._img_hash = imagehash.phash(im)
        return self._img_hash

    def diff(self, e2):
        """ Difference of two element, score range from 0-100, 0 for identical, 100 for totally different """
        assert isinstance(e2, UniqueElement)
        # two elements are not in the same activity
        if not self.page.id == e2.page.id:
            return 100
        for k in ['class_name', 'res_id', 'text', 'desc']:
            if not self.info.get(k) == e2.info.get(k):
                return 99
        hash1 = self.img_hash
        hash2 = e2.img_hash
        maxdiff = max(hash1.hash.size, hash2.hash.size)  # this normalization is problematic
        return (hash1 - hash2) * 100 / maxdiff

    def get_web_element(self, driver=None):
        """ Return WebElement instance of the element """
        if isinstance(self._element, StaticElement):
            assert driver.__class__.__name__ == 'WebDriver'
            xpath = self._element.page.get_xpath(self._element.element)
            elements = driver.find_elements_by_xpath(xpath)
            if not elements:
                raise Exception('Cannot find element with given XPath: {}'.format(xpath))
            if len(elements) > 1:
                logger.warning('Multiple elements match XPath: %s', xpath)
            return elements[0]
        else:
            return self._element

    @staticmethod
    def _crop_bounds(im, bounds):
        """ Crop element image from screen image given its bounds """
        box = tuple(map(int, [bounds[0][0], bounds[0][1], bounds[1][0], bounds[1][1]]))
        return im.crop(box).convert('RGB')

    @property
    def screenshot(self):
        """ Return image object of the element's screenshot """
        if self._screenshot is None:
            if self._static:
                assert self._screen_im is not None
                screenshot = self._crop_bounds(self._screen_im, self.info.bounds)
            else:
                screenshot = Image.open(BytesIO(self._element.screenshot_as_png())).convert('RGB')
            self._screenshot = screenshot
        return self._screenshot

    def set_score_config(self, config):
        self._config = config

    def _str_score(self, s):
        MAX_LEN = 20
        max_score = 0
        s = s.lower()
        s_len = len(s)
        groups = self._config['KEYWORD_WEIGHTS']
        # get length of matched parts
        all_kw = reduce(operator.concat, [d['keywords'].split('|') for d in groups])
        matched_kw = [kw for kw in all_kw if kw in s]
        matched_len = min(s_len, sum(map(len, matched_kw)))
        # calculate score of string s, keep the max among keywords
        for d in groups:
            for kw in d['keywords'].split('|'):
                if kw in s:
                    # http://www.wolframalpha.com/input/?i=plot+(20-x)%2F(20*1.1%5Ex)+from+0+to+20
                    # x is the total length of unmatched parts
                    x = min(MAX_LEN, s_len - matched_len)
                    k = 1.1  # larger the k is, steeper the graph decrease near x=0
                    len_eff = (1 - x / MAX_LEN) / (k**x)
                    score = len_eff * d['weight']
                    if score > max_score:
                        max_score = score
        return max_score

    def _class_score(self, s):
        for c, w in self._config['CLASS_WEIGHTS'].items():
            if c in s:
                return w
            else:
                return 0

    # TODO: finish this
    def _pos_score(self, bounds):
        """ Score by both position and size of an element """
        pass

    @property
    def score(self):
        """ Score of the element with configuration """
        if not self._score:
            w = self._config['OVERALL_WEIGHTS']
            self._score += w['text'] * self._str_score(self.info.text)
            res_id_str = self.info.res_id.split('/')[-1]
            self._score += w['res_id'] * self._str_score(res_id_str)
            self._score += w['desc'] * self._str_score(self.info.desc)
            self._score += w['class'] * self._class_score(self.info.class_name)
            assert isinstance(self._element, StaticElement)
            real_clickable = 1 if self.page.in_clickable_area(self._element.element) else 0 
            self._score += w['clickable'] * real_clickable
            # logger.verbose(u'{}:\t{} = {}*{} + {}*{} + {}*{} + {}*{} + {}*{}'.format(
            #     self.info, self._score,
            #     w['text'], self._str_score(self.info.text),
            #     w['res_id'], self._str_score(res_id_str),
            #     w['desc'], self._str_score(self.info.desc),
            #     w['class'], self._class_score(self.info.class_name),
            #     w['clickable'], real_clickable))
        return self._score


class ElementInfo(object):
    """
    Object storing basic element information.
        Information are cached once retrieved for performance optimization.
        The input element can be either a WebElement or a StaticElement.
    """
    def __init__(self, element):
        if isinstance(element, StaticElement):
            e = element.element
            self._class_name = e.get('class')
            self._text = e.get('text')
            self._res_id = e.get('resource-id')
            self._desc = e.get('content-desc')
            nums = map(int, re.findall(r"\d+", e.get('bounds')))
            self._bounds = ((nums[0], nums[1]), (nums[2], nums[3]))
            self._clickable = True if e.get('clickable') == "true" else False
        else:
            self._element = element
            self._class_name = None
            self._text = None
            self._res_id = None
            self._desc = None
            self._bounds = None
            self._clickable = None

    def get(self, attr_name):
        return getattr(self, attr_name)

    @property
    def class_name(self):
        if self._class_name is None:
            try:
                class_name = self._element.get_attribute('className')
                if not class_name:
                    class_name = ""
            except NoSuchElementException:
                class_name = ""
            self._class_name = class_name
        return self._class_name

    @property
    def text(self):
        if self._text is None:
            try:
                text = self._element.text
                if not text:
                    text = ""
            except NoSuchElementException:
                text = ""
            self._text = text
        return self._text

    @property
    def res_id(self):
        if self._res_id is None:
            try:
                res_id = self._element.get_attribute('resourceId')
                if not res_id:
                    res_id = ""
            except NoSuchElementException:
                res_id = ""
            self._res_id = res_id
        return self._res_id

    @property
    def desc(self):
        if self._desc is None:
            try:
                desc = self._element.get_attribute('contentDescription')
                if not desc:
                    desc = ""
            except NoSuchElementException:
                desc = ""
            self._desc = desc
        return self._desc

    @property
    def bounds(self):
        if self._bounds is None:
            try:
                x, y = self._element.location['x'], self._element.location['y']
                width, height = self._element.size['width'], self._element.size['height']
                bounds = ((x, y) , (x + width, y + height))
            except Exception:
                bounds = ""
            self._bounds = bounds
        return self._bounds

    @property
    def clickable(self):
        if self._clickable is None:
            try:
                clickable = self._element.get_attribute('clickable')
                if clickable == "true":
                    clickable = True
                else:
                    clickable = False
            except NoSuchElementException:
                clickable = False
            self._clickable = clickable
        return self._clickable

    def __repr__(self):
        return u"<{}>".format(u','.join([self.class_name, self.text, self.res_id, self.desc]))