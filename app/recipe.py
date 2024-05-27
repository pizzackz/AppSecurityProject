class Recipe:
    count_id = 0

    """
    Attributes to be added:
    - Date created
    - User created
    - Type (Standard or Premium)
    - Calories
    - Prep time
    """

    def __init__(self, name, ingredients, instructions, picture):
        Recipe.count_id += 1
        self.__id = str(Recipe.count_id)
        self.__name = name
        self.__ingredients = ingredients
        self.__instructions = instructions
        self.__picture = picture


    def get_id(self):
        return self.__id

    def set_name(self, name):
        self.__name = name

    def get_name(self):
        return self.__name

    def set_ingredients(self, ingredients):
        self.__ingredients = ingredients

    def get_ingredients(self):
        return self.__ingredients

    def set_instructions(self, instructions):
        self.__instructions = instructions

    def get_instructions(self):
        return self.__instructions

    def get_picture(self):
        return self.__picture

    def set_picture(self, picture):
        self.__picture = picture

