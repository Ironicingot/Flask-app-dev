class Review:
    def __init__(self, review_id, rating, feedback):
        self.review_id = review_id
        self.rating = rating
        self.feedback = feedback

    def get_review_id(self):
        return self.review_id
    def set_rating(self, review_id):
        self.review_id = review_id

    def get_rating(self):
        return self.rating
    def set_rating(self, rating):
        self.rating = rating

    def get_feedback(self):
        return self.feedback
    def set_feedback(self, feedback):
        self.feedback = feedback
