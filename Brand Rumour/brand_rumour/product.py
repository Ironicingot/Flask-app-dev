class Product:

    def __init__(self, name, price, size, category, image):
        self._name = name
        self._price = price
        self._category = category
        self._size = size
        self._image = image

    def get_size(self):
        return self._size

    def get_image(self):
        return self._image

    def get_name(self):
        return self._name

    def get_price(self):
        return self._price

    def get_category(self):
        return self._category

    def set_name(self, name):
        self._name = name

    def set_price(self, price):
        self._price = price

    def set_category(self, category):
        self._category = category

    def set_size(self, size):
        self._size = size

    def set_category(self, image):
        self._image = image