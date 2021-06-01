# -*- coding: utf-8 -*-
# tips:
from flask_wtf import FlaskForm
from wtforms import Form, StringField, DateTimeField, SelectMultipleField,SubmitField,validators

class SearchEventForm(FlaskForm):
    # DateTimeField
    startdate=DateTimeField(label='时间查询: ')
    enddate=DateTimeField(label='~')

    # IP text
    ip=StringField(
        label='IP地址: ',
        validators=[
            validators.Regexp('(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)')
        ]
    )

    # Attack Type
    attacktype=SelectMultipleField(
        label='攻击类型: ',
        choices=[('爆破','爆破'),('py','Python'),('text','Plain Text')],
        render_kw={
            'id':"sel_attacktype",
            'multiple':"multiple",
            'class':"select2-container--default"
        }
    )

    # Protocol tyoe
    protocoltype = SelectMultipleField(
        label='协议类型: ',
        choices=[('TCP', 'TCP'), ('UDP', 'UDP')],
        render_kw={
            'id': "sel_protocoltype",
            'multiple': "multiple",
            'class': "select2-container--default"
        }
    )


    # 攻击详情搜索 Mode Search
    detail=StringField(label='攻击详情(模糊): ')

    submit=SubmitField(label='搜索')

