def is_list_subset_another(subset_lst, lst):

    if subset_lst is lst:
        return True

    criteria = []

    for subitem in subset_lst:
        subset = subitem.items()
        item_is_subset = False

        for item in lst:
            if subset <= item.items():
                item_is_subset = True
                break

        criteria.append(item_is_subset)

    return all(criteria)


class AssertList:
    def __init__(self, lst):
        self.lst = lst

    def subset_of(self, other_lst):
        return is_list_subset_another(self.lst, other_lst)

    def has_subset(self, other_lst):
        return is_list_subset_another(other_lst, self.lst)

    def __ge__(self, other_list):
        return self.has_subset(other_list)

    def __le__(self, other_list):
        return self.subset_of(other_list)


def pytest_assertrepr_compare(config, op, left, right):

    if isinstance(left, AssertList) and op in {"<=", ">="}:

        statement = f"{left.lst} {op} {right}"

        return [statement]


list_is = AssertList  # noqa: F841
