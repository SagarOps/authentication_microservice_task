from datetime import datetime
from django.core.exceptions import ObjectDoesNotExist
from decimal import Decimal
import math

date_formatting_day_month_date_year = "%A, %b %d, %Y"

def date_formatting(self):
    # sample date format - October 19, 2023
    if 'T' in self:
        return datetime.strptime(self.split('T')[0], '%Y-%m-%d').strftime('%B %e, %Y')

def get_or_raise(model, obj_id, error_message):
    if obj_id:
        try:
            return model.objects.get(id=obj_id)
        except model.DoesNotExist:
            raise ObjectDoesNotExist(error_message)
    return model.objects.all()
