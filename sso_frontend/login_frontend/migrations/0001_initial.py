# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'Browser'
        db.create_table(u'login_frontend_browser', (
            ('bid', self.gf('django.db.models.fields.CharField')(max_length=37, primary_key=True)),
            ('username', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['login_frontend.User'], null=True)),
            ('ua', self.gf('django.db.models.fields.CharField')(max_length=250)),
            ('created', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('modified', self.gf('django.db.models.fields.DateTimeField')(auto_now=True, blank=True)),
            ('save_browser', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('auth_level', self.gf('django.db.models.fields.CharField')(default='0', max_length=1)),
            ('auth_level_valid_until', self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True)),
            ('auth_state', self.gf('django.db.models.fields.CharField')(default='0', max_length=1)),
            ('auth_state_valid_until', self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True)),
        ))
        db.send_create_signal(u'login_frontend', ['Browser'])

        # Adding model 'BrowserUsers'
        db.create_table(u'login_frontend_browserusers', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('username', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['login_frontend.User'])),
            ('browser', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['login_frontend.Browser'])),
            ('auth_timestamp', self.gf('django.db.models.fields.DateTimeField')()),
            ('current_auth_level', self.gf('django.db.models.fields.CharField')(default='0', max_length=1)),
            ('max_auth_level', self.gf('django.db.models.fields.CharField')(default='0', max_length=1)),
        ))
        db.send_create_signal(u'login_frontend', ['BrowserUsers'])

        # Adding model 'User'
        db.create_table(u'login_frontend_user', (
            ('username', self.gf('django.db.models.fields.CharField')(max_length=50, primary_key=True)),
            ('strong_enabled', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('strong_phone', self.gf('django.db.models.fields.CharField')(max_length=30, null=True, blank=True)),
        ))
        db.send_create_signal(u'login_frontend', ['User'])


    def backwards(self, orm):
        # Deleting model 'Browser'
        db.delete_table(u'login_frontend_browser')

        # Deleting model 'BrowserUsers'
        db.delete_table(u'login_frontend_browserusers')

        # Deleting model 'User'
        db.delete_table(u'login_frontend_user')


    models = {
        u'login_frontend.browser': {
            'Meta': {'object_name': 'Browser'},
            'auth_level': ('django.db.models.fields.CharField', [], {'default': "'0'", 'max_length': '1'}),
            'auth_level_valid_until': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'auth_state': ('django.db.models.fields.CharField', [], {'default': "'0'", 'max_length': '1'}),
            'auth_state_valid_until': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'bid': ('django.db.models.fields.CharField', [], {'max_length': '37', 'primary_key': 'True'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'save_browser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'ua': ('django.db.models.fields.CharField', [], {'max_length': '250'}),
            'username': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']", 'null': 'True'})
        },
        u'login_frontend.browserusers': {
            'Meta': {'object_name': 'BrowserUsers'},
            'auth_timestamp': ('django.db.models.fields.DateTimeField', [], {}),
            'browser': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.Browser']"}),
            'current_auth_level': ('django.db.models.fields.CharField', [], {'default': "'0'", 'max_length': '1'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'max_auth_level': ('django.db.models.fields.CharField', [], {'default': "'0'", 'max_length': '1'}),
            'username': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['login_frontend.User']"})
        },
        u'login_frontend.user': {
            'Meta': {'object_name': 'User'},
            'strong_enabled': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'strong_phone': ('django.db.models.fields.CharField', [], {'max_length': '30', 'null': 'True', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '50', 'primary_key': 'True'})
        }
    }

    complete_apps = ['login_frontend']