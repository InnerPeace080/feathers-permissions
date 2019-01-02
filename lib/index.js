const _ = require('lodash');
const { Forbidden } = require('@feathersjs/errors');
const debug = require('debug')('feathers-permissions');

function processRole(context,role,rolesInfo){
  debug(`processRole`, rolesInfo);
  const roleInfo = rolesInfo.find(c=>c.name === role)
  if (!roleInfo) {throw new Error(`role ${role} is not defined`);}
  const roleUrlInfo = roleInfo.permissions.find(c=>((c.url===context.path && c.method === context.method) ||
                                                    (c.url==='all' && c.method === context.method) ||
                                                    (c.url===context.path && c.method === 'all') ||
                                                    (c.url==='all' && c.method === 'all') ))
  if (!roleUrlInfo) {throw new Forbidden('You do not have the correct permissions (invalid permission entity).');}
  debug(`roleUrlInfo`, roleUrlInfo);
  if (roleUrlInfo.limit && roleUrlInfo.limit.restrict) {
    roleUrlInfo.limit.restrict.forEach((restrictInfo)=>{
      var idValue
      if (restrictInfo.idField) {
        idValue = _.get(context.params,`${restrictInfo.entity||'user'}.${restrictInfo.idField}`)
      }else if(restrictInfo.idValue){
        idValue = restrictInfo.idValue
      }

      if (idValue !== undefined && restrictInfo.ownerField) {
        context.params.query = context.params.query || {}
        context.params.query[restrictInfo.ownerField] = idValue
      }
    })
    debug(`after restrict`, context.params.query);
  }

  if (roleUrlInfo.limit &&
        (context.method === 'create' || context.method === 'update' || context.method === 'patch' ) &&
          roleUrlInfo.limit.custom) {
    let processField = (data,fieldInfo)=>{
      if (!fieldInfo.field) {return;}
      let currentField = _.get(data,fieldInfo.field)
      if (currentField !== undefined && fieldInfo.range) {
        if (Array.isArray( currentField )) {
          let checkAllow = currentField.every((c)=>{
            return fieldInfo.range.includes(c)
          })
          if (!checkAllow) {
            throw new Forbidden(`You do not have the correct permissions to set ${fieldInfo.field} equal ${currentField} `);
          }
        }else{
          if(!fieldInfo.range.includes(currentField)){
            throw new Forbidden(`You do not have the correct permissions to set ${fieldInfo.field} equal ${currentField} `);
          }
        }
      }else if(fieldInfo.default !== undefined){
        _.set(data,fieldInfo.field,fieldInfo.default)
      }
    }
    roleUrlInfo.limit.custom.forEach((fieldInfo)=>{
      if (Array.isArray(context.data)) {
        context.data.forEach(c=>{
          processField(c,fieldInfo)
        })
      }else{
        processField(context.data,fieldInfo)
      }
    })
    debug(`after custom`, context.data);
  }

  return context

}

module.exports = function checkPermissions (options = {}) {
  options = Object.assign({
    entity: 'user',
    field: 'permissions'
  }, options);

  const { entity: entityName, field, roles } = options;

  return function (context) {
    return Promise.resolve(typeof roles === 'function' ? roles(context) : roles).then(currentRoles => {
      if (context.type !== 'before') {
        return Promise.reject(new Error(`The feathers-permissions hook should only be used as a 'before' hook.`));
      }
      if (!context.rolesInfo && !Array.isArray(roles) && typeof roles !== 'function') {
        throw new Error(`'roles' option for feathers-permissions hook must be an array or a function or must provide rolesInfo`);
      }

      debug('Running checkPermissions hook with options:', options);
      const entity = context.params[entityName];
      const rolesInfo = context.rolesInfo

      if (!entity) {
        debug(`context.params.${entityName} does not exist. If you were expecting it to be defined check your hook order and your idField options in your auth config.`);
        if (context.params.provider) {
          throw new Forbidden('You do not have the correct permissions (invalid permission entity).');
        }

        return context;
      }

      const method = context.method;
      let permissions = entity[field] || [];

      // Normalize permissions. They can either be a
      // comma separated string or an array.
      if (typeof permissions === 'string') {
        permissions = permissions.split(',').map(current => current.trim());
      }

      const requiredPermissions = currentRoles
      // [
      //   '*',
      //   `*:${method}`
      // ];
      //
      // currentRoles.forEach(role => {
      //   requiredPermissions.push(
      //     `${role}`,
      //     `${role}:*`,
      //     `${role}:${method}`
      //   );
      // });

      if (requiredPermissions) {
        debug(`Required Permissions`, requiredPermissions);
        const permitted = permissions.some(permission => requiredPermissions.includes(permission) || requiredPermissions.includes(`${permission}:${method}`) );
        context.params.permitted = context.params.permitted || permitted;
      }else if(rolesInfo){
        debug(`Required Permissions rolesInfo`, rolesInfo);
        permissions.some((role)=>{
          context = processRole(context,role,rolesInfo)
          context.params.permitted = true;
          return context
        })
      }else{
        debug(`Required Permissions no requiredPermissions neither rolesInfo`, rolesInfo);
      }

      if (context.params.provider && options.error !== false && !context.params.permitted) {
        throw new Forbidden('You do not have the correct permissions.');
      }

      return context;
    });
  };
};
