const _ = require('lodash');
const { Forbidden,GeneralError } = require('@feathersjs/errors');
const debug = require('debug')('feathers-permissions');

function isObject(val) {
    if (val === null) { return false;}
    return ( (typeof val === 'function') || (typeof val === 'object') );
}

function processRole(context,role,rolesInfo){
  debug(`processRole`, rolesInfo);
  if (!rolesInfo) {return false;} // throw new Error(`rolesInfo is not defined`);}
  const roleInfo = rolesInfo.find(c=>c.name === role)
  if (!roleInfo) {return false;} // throw new Error(`role ${role} is not defined`);}
  if (roleInfo.forbidden) {return false;}
  const roleUrlInfo = roleInfo.permissions.find(c=>((c.url===context.path && c.method === context.method) ||
                                                    (c.url==='all' && c.method === context.method) ||
                                                    (c.url===context.path && c.method === 'all') ||
                                                    (c.url==='all' && c.method === 'all') ))
  if (!roleUrlInfo) {return false;} //{throw new Forbidden('You do not have the correct permissions (invalid permission entity).');}
  debug(`roleUrlInfo`, roleUrlInfo);
  if (roleUrlInfo.limit && roleUrlInfo.limit.whiteList &&
        Array.isArray(roleUrlInfo.limit.whiteList) && roleUrlInfo.limit.whiteList.length>0) {
    let passWhiteList = roleUrlInfo.limit.whiteList.some((fieldInfo)=>{
      if (fieldInfo.idField && fieldInfo.idValue) {
        let idValue = _.get(context.params,`${fieldInfo.entity||'user'}.${fieldInfo.idField}`)
        if (fieldInfo.idValue.includes(idValue)) {
          return true;
        }else{
          return false;
        }
      }
      return true;
    })
    if (!passWhiteList) {throw new Forbidden('You do not have the correct permissions.');}
  }
  if (roleUrlInfo.limit && roleUrlInfo.limit.blackList &&
        Array.isArray(roleUrlInfo.limit.blackList) && roleUrlInfo.limit.blackList.length>0) {
    let noPassBlackList = roleUrlInfo.limit.blackList.some((fieldInfo)=>{
      if (fieldInfo.idField && fieldInfo.idValue) {
        let idValue = _.get(context.params,`${fieldInfo.entity||'user'}.${fieldInfo.idField}`)
        if (fieldInfo.idValue.includes(idValue)) {
          return true;
        }
      }
      return false;
    })
    if (noPassBlackList) {throw new Forbidden('You do not have the correct permissions.');}
  }

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
        if ((restrictInfo.ownerField === '$populate' || restrictInfo.ownerField === '$select') && context.params.query[restrictInfo.ownerField]) {
          if (!Array.isArray(idValue)) {
            idValue = [idValue]
          }
          context.params.query[restrictInfo.ownerField] = idValue.concat(context.params.query[restrictInfo.ownerField])
        }else{
          context.params.query[restrictInfo.ownerField] = idValue
        }
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
      if(fieldInfo.force !== undefined){
        if ( isObject(fieldInfo.force) && fieldInfo.force.clear) {
          delete data[fieldInfo.field]
        }else if ( isObject(fieldInfo.force) && fieldInfo.force.idField) {
          let idValue = _.get(context.params,`${fieldInfo.force.entity||'user'}.${fieldInfo.force.idField}`)
          if (idValue!==undefined) {
            _.set(data,fieldInfo.field,idValue)
          }else{
            throw new GeneralError(`${fieldInfo.force.entity||'user'}.${fieldInfo.force.idField} is not existed`);
          }
        }else{
          _.set(data,fieldInfo.field,fieldInfo.force)
        }
      }else if (currentField !== undefined && fieldInfo.range) {
        let rangeValue = fieldInfo.range.map((c)=>{
          if (isObject(c)  && c.idField) {
            let idValue = _.get(context.params,`${c.entity||'user'}.${c.idField}`)
            return idValue
          }else{
            return c
          }
        })

        if (Array.isArray( currentField )) {
          let checkAllow = currentField.every((c)=>{
            return rangeValue.includes(c)
          })
          if (!checkAllow) {
            // throw new Forbidden(`You do not have the correct permissions to set ${fieldInfo.field} equal ${currentField} `);
            return false;
          }
        }else{
          if(!rangeValue.includes(currentField)){
            // throw new Forbidden(`You do not have the correct permissions to set ${fieldInfo.field} equal ${currentField} `);
            return false;
          }
        }
      }else if(fieldInfo.default !== undefined){
        if ( isObject(fieldInfo.default) && fieldInfo.default.idField) {
          let idValue = _.get(context.params,`${fieldInfo.default.entity||'user'}.${fieldInfo.default.idField}`)
          if (idValue!==undefined) {
            _.set(data,fieldInfo.field,idValue)
          }
        }else{
          _.set(data,fieldInfo.field,fieldInfo.default)
        }
      }
      return true
    }
    return roleUrlInfo.limit.custom.every((fieldInfo)=>{
      if (Array.isArray(context.data)) {
        return context.data.every(c=>{
          return processField(c,fieldInfo)
        })
      }else{
        return processField(context.data,fieldInfo)
      }
    })
    debug(`after custom`, context.data);
  }

  return true

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
        const permitted = permissions.some((role)=>{
          return processRole(context,role,rolesInfo)
        })
        context.params.permitted = context.params.permitted || permitted;
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
