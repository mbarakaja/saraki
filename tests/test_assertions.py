import pytest
from assertions import list_is


dummy_lst = [{"name": "Elmer"}, {"name": "Sam"}]


params = (
    ("lst", "subset_lst", "expected"),
    [
        ([], [], True),
        ([{}, {}], [{}, {}, {}], True),
        (
            [{"id": 1, "name": "Jon", "pets": []}, {"id": 2, "name": "Sam"}],
            [{"id": 1, "pets": []}],
            True,
        ),
        ([{"id": 1}], [{"id": 1, "name": "Jon"}, {"id": 2, "name": "Sam"}], False),
        ([{"id": 1}], [{"id": 1, "name": "Elmer"}], False),
        (
            [{"id": 1, "name": "Elmer"}, {"id": 2, "name": "Sam"}],
            [{"id": 1, "name": "Elmer"}, {"id": 2, "name": "Sam"}],
            True,
        ),
        (dummy_lst, dummy_lst, True),
    ],
)


@pytest.mark.parametrize(*params)
def test_list_is_subset_of(lst, subset_lst, expected):

    if expected is True:
        assert list_is(subset_lst).subset_of(lst)
        assert list_is(subset_lst) <= lst
    else:
        assert not list_is(subset_lst).subset_of(lst)
        assert not list_is(subset_lst) <= lst


@pytest.mark.parametrize(*params)
def test_list_has_subset(lst, subset_lst, expected):

    if expected is True:
        assert list_is(lst).has_subset(subset_lst)
        assert list_is(lst) >= subset_lst
    else:
        assert not list_is(lst).has_subset(subset_lst)
        assert not list_is(lst) >= subset_lst
