# -*- coding: utf-8 -*-

from django.contrib.auth import get_user_model

from . import is_allowed, is_denied


class DSM(object):
    def __init__(self, model, access_model):
        self.model = model
        self.access_model = access_model

        self.data = None
        self.size_x = 0
        self.size_y = 0
        self.ids_x = None
        self.ids_y = None
        self.names_x = None
        self.names_y = None
        self.objects_x = None
        self.objects_y = None

        self.data_implicit = None
        self.size_x_implicit = 0
        self.size_y_implicit = 0
        self.objects_x_implicit = None
        self.objects_y_implicit = None
        self.names_x_implicit = None
        self.names_y_implicit = None

    def compute(self, reverse=False, filters=None, orders=None):
        user_model = get_user_model()
        x, y = 'res', 'usr'
        if reverse:
            x, y = y, x
        objects = self.access_model.objects.all()
        if filters:
            objects = self.access_model.objects.filter(filters)
        if not orders:
            orders = []
        for order in orders:
            objects = objects.order_by(order)

        self.size_x = objects.values(x).distinct().count()
        self.size_y = objects.values(y).distinct().count()

        matrix_data = [[[] for _x in range(self.size_x)]
                       for _y in range(self.size_y)]
        set_x, set_y = {}, {}
        count_x, count_y = 0, 0
        for obj in objects:
            id_x = getattr(obj, x)
            id_y = getattr(obj, y)

            mem_x = set_x.get(id_x, None)
            if mem_x is None:
                set_x[id_x] = count_x
                index_x = count_x
                count_x += 1
            else:
                index_x = mem_x

            mem_y = set_y.get(id_y, None)
            if mem_y is None:
                set_y[id_y] = count_y
                index_y = count_y
                count_y += 1
            else:
                index_y = mem_y

            matrix_data[index_y][index_x].append(obj.val)

        self.data = matrix_data
        self.ids_x = [
            i[0]
            for i in sorted(
                [(k, v) for k, v in set_x.items()], key=lambda l: l[1])
        ]
        self.ids_y = [
            i[0]
            for i in sorted(
                [(k, v) for k, v in set_y.items()], key=lambda l: l[1])
        ]

        if reverse:
            self.objects_x = [user_model.objects.get(id=i) for i in self.ids_x]
            self.objects_y = [
                self.model.objects.get(id=i) if i else None for i in self.ids_y
            ]
            self.names_x = [str(o) for o in self.objects_x]
            self.names_y = [
                str(o) if o else '** All **' for o in self.objects_y
            ]
        else:
            self.objects_x = [
                self.model.objects.get(id=i) if i else None for i in self.ids_x
            ]
            self.objects_y = [user_model.objects.get(id=i) for i in self.ids_y]
            self.names_x = [
                str(o) if o else '** All **' for o in self.objects_x
            ]
            self.names_y = [str(o) for o in self.objects_y]

        return self.data

    def compute_implicit(self,
                         reverse=False,
                         user_filters=None,
                         user_orders=None,
                         resource_filters=None,
                         resource_orders=None):
        user_model = get_user_model()
        users = user_model.objects.all()
        resources = self.model.objects.all()

        if user_filters:
            users = users.filter(**user_filters)
        if user_orders:
            for order in user_orders:
                users = users.order_by(order)
        if resource_filters:
            resources = resources.filter(**resource_filters)
        if resource_orders:
            for order in resource_orders:
                resources = resources.order_by(order)

        def i_p_default(u, r):
            return self.access_model.implicit_perms(u, r)

        def i_p_reverse(r, u):
            return self.access_model.implicit_perms(u, r)

        implicit_perms = i_p_default
        x, y = resources, users
        if reverse:
            implicit_perms = i_p_reverse
            x, y = y, x

        self.size_x_implicit = x.count()
        self.size_y_implicit = y.count()

        matrix_data = [[None for _x in range(self.size_x_implicit)]
                       for _y in range(self.size_y_implicit)]
        for index_y, obj_y in enumerate(y):
            for index_x, obj_x in enumerate(x):
                matrix_data[index_y][index_x] = implicit_perms(obj_y, obj_x)

        self.data_implicit = matrix_data
        self.objects_x_implicit = x
        self.objects_y_implicit = y
        self.names_x_implicit = [str(r) for r in x]
        self.names_y_implicit = [str(u) for u in y]

        return self.data_implicit

    def to_highcharts_heatmap(self, implicit=False, **kwargs):
        if implicit:
            if not self.data_implicit:
                self.compute_implicit(**kwargs)
            categories_x = self.names_x_implicit
            categories_y = self.names_y_implicit
            size_x, size_y = self.size_x_implicit, self.size_y_implicit
            data = self.data_implicit
        else:
            if not self.data:
                self.compute(**kwargs)
            categories_x, categories_y = self.names_x, self.names_y
            size_x, size_y = self.size_x, self.size_y
            data = self.data

        def rights_to_value(rights, implicit=False):
            if implicit:
                return len(rights)
            n_deny = len([p for p in rights if is_denied(p)])
            n_allow = len([p for p in rights if is_allowed(p)])
            return -1 * n_deny + n_allow

        pixel_by_line = 40 if size_y < 10 else 18
        pixel_by_column = 50 if size_x < 30 else 25

        values = {(x, y): rights_to_value(
            data[y][x], implicit=implicit)
                  for x in range(size_x) for y in range(size_y) if data[y][x]}

        chart_dict = {
            'chart': {
                'type': 'heatmap',
                'marginTop': 40,
                'marginBottom': 80,
                'plotBorderWidth': 1,
                'height': size_y * pixel_by_line + 120,
                'width': size_x * pixel_by_column + 120
            },
            'title': {
                'text': None
            },
            'xAxis': {
                'categories': categories_x,
                'title': {
                    'text': None
                }
            },
            'yAxis': {
                'categories': categories_y,
                'title': {
                    'text': None
                }
            },
            'colorAxis': {
                'minColor': '#0000FF',
                'maxColor': '#FF0000'
            },
            'legend': {
                'align': 'right',
                'layout': 'vertical',
                'margin': 0,
                'verticalAlign': 'top',
                'y': 23,
                'reversed': True,
                'symbolHeight': size_y * pixel_by_line
            },
            'tooltip': {
                'formatter':
                "return '<b>' + this.series.yAxis.categories[this.point.y]"
                " + '</b><br>' + '<b>' + this.point.perms + '</b><br>' + "
                "'<b>' + this.series.xAxis.categories[this.point.x] + '</b>';"
            },
            'series': [{
                'name': None,
                'borderWidth': 1,
                'data': [
                    {
                        'x': x,
                        'y': y,
                        'value': values[(x, y)],
                        # 'color': colors[(x, y)],
                        'perms': data[y][x]
                    } for x in range(size_x) for y in range(size_y)
                    if data[y][x]
                ],
                'dataLabels': {
                    'enabled': False
                }
            }]
        }

        return chart_dict
