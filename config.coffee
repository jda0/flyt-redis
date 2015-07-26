module.exports = config = {}

config.API_KEY_LENGTH     = 12
config.API_SECRET_LENGTH  = 12
config.ETOKEN_LENGTH      = 3

config.API_KEY_EXPIRE     = 86400 * 7
config.ETOKEN_EXPIRE      = 86400
config.NEW_USER_EXPIRE    = 86400 * 28

config.MANDRILL_EMAIL     = ''
config.MANDRILL_KEY       = ''
config.REDIS_HOST         = '127.0.0.1'
config.REDIS_PORT         = 6379
config.REDIS_PASS         = ''

config.ACL_FLAGS =
  'READ'                  : 1
  'ADD_REPORTS'           : 2
  'COMMENT_REPORTS'       : 4
  'EDIT_REPORTS'          : 8
  'DELETE_REPORTS'        : 16
  'ADD_PEOPLE'            : 128
  'EDIT_PEOPLE'           : 256
  'VOID_PEOPLE'           : 512
  'ADD_GROUPINGS'         : 1024
  'EDIT_GROUPINGS'        : 2048
  'TRUST_USERS'           : 8192
  'VOID_USERS'            : 16384
  'SET_ACL'               : 32768

config.ROLES =
  'Read Only'             : config.ACL_FLAGS.READ
  'Limited'               : config.ACL_FLAGS.READ |
                            config.ACL_FLAGS.ADD_REPORTS |
                            config.ACL_FlAGS.COMMENT_REPORTS
  'Moderator'             : config.ACL_FLAGS.READ |
                            config.ACL_FLAGS.ADD_REPORTS |
                            config.ACL_FlAGS.COMMENT_REPORTS |
                            config.ACL_FLAGS.EDIT_REPORTS |
                            config.ACL_FLAGS.DELETE_REPORTS |
                            config.ACL_FLAGS.TRUST_USERS
  'Admin'                 : 65535

config.REPORT_TYPES = [
  'SeriousConcern'
  'MinorConcern'
  'Praise'
  'Award'
  'Event'
]
