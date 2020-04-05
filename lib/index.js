const _ = require('lodash');
const { Forbidden, GeneralError } = require('@feathersjs/errors');
const debug = require('debug')('feathers-permissions');

function isObject(val) {
  if (val === null) { return false;}

  return ( (typeof val === 'function') || (typeof val === 'object') );
}

function processRole(context, role, rolesInfo, options={}){
  debug('processRole', rolesInfo);
  if (!rolesInfo) {return false;} // throw new Error(`rolesInfo is not defined`);}
  const roleInfo = rolesInfo.find((c)=>c.name === role);

  if (!roleInfo) {return false;} // throw new Error(`role ${role} is not defined`);}
  if (roleInfo.forbidden) {throw new Forbidden('You do not have the correct permissions.');}
  const roleUrlInfo = roleInfo.permissions.find((c)=>((c.url===context.path && c.method === context.method) ||
                                                    (c.url==='all' && c.method === context.method) ||
                                                    (c.url===context.path && c.method === 'all') ||
                                                    (c.url==='all' && c.method === 'all') ));

  if (!roleUrlInfo) {return false;} //{throw new Forbidden('You do not have the correct permissions (invalid permission entity).');}
  debug('roleUrlInfo', roleUrlInfo);
  if (roleUrlInfo.forbidden) {throw new Forbidden('You do not have the correct permissions.');}
  if (roleUrlInfo.limit && roleUrlInfo.limit.whiteList &&
        Array.isArray(roleUrlInfo.limit.whiteList) && roleUrlInfo.limit.whiteList.length>0) {
    const passWhiteList = roleUrlInfo.limit.whiteList.some((fieldInfo)=>{
      if (fieldInfo.idField && fieldInfo.idValue) {
        const idValue = _.get(context.params, `${fieldInfo.entity||'user'}.${fieldInfo.idField}`);

        if (fieldInfo.idValue.includes(idValue) ||
              ((typeof idValue === 'object')&& fieldInfo.idValue.includes(idValue.toString())) ) {
          return true;
        }else{
          return false;
        }
      }

      return false;
    });

    if (!passWhiteList) {throw new Forbidden('You do not have the correct permissions.');}
  }
  if (roleUrlInfo.limit && roleUrlInfo.limit.blackList &&
        Array.isArray(roleUrlInfo.limit.blackList) && roleUrlInfo.limit.blackList.length>0) {
    const noPassBlackList = roleUrlInfo.limit.blackList.some((fieldInfo)=>{
      if (fieldInfo.idField && fieldInfo.idValue) {
        const idValue = _.get(context.params, `${fieldInfo.entity||'user'}.${fieldInfo.idField}`);

        if (fieldInfo.idValue.includes(idValue) ||
              ((typeof idValue === 'object')&& fieldInfo.idValue.includes(idValue.toString())) ) {
          return true;
        }
      }

      return false;
    });

    if (noPassBlackList) {throw new Forbidden('You do not have the correct permissions.');}
  }

  context.params.skipPostRestrict = roleUrlInfo.limit && roleUrlInfo.limit.skipPostRestrict;

  if (roleUrlInfo.limit && roleUrlInfo.limit.restrict) {
    roleUrlInfo.limit.restrict.forEach((restrictInfo)=>{
      var idValue;

      if (restrictInfo.idField) {
        idValue = _.get(context.params, `${restrictInfo.entity||'user'}.${restrictInfo.idField}`);
      }else if(restrictInfo.idValue){
        idValue = restrictInfo.idValue;
      }

      if (idValue !== undefined && restrictInfo.ownerField) {
        if(restrictInfo.ownerField === '__id__' &&
            (context.method === 'get' || context.method === 'remove' || context.method === 'update' || context.method === 'patch')){
          context.id = idValue;
        }else{
          context.params.query = context.params.query || {};
          if ((restrictInfo.ownerField === '$populate' || restrictInfo.ownerField === '$select') && context.params.query[restrictInfo.ownerField]) {
            if (!Array.isArray(idValue)) {
              idValue = [idValue];
            }
            context.params.query[restrictInfo.ownerField] = idValue.concat(context.params.query[restrictInfo.ownerField]);
          }else{
            context.params.query[restrictInfo.ownerField] = idValue;
          }
        }
      }
    });
    debug('after restrict', context.params.query);
  }

  // avoid remove, patch, update all
  if(options.preventEditAll){
    if(context.method === 'remove' || context.method === 'update' || context.method === 'patch'){
      if(!context.id && (!context.params || !context.params.query || Object.keys(context.params.query).length == 0)){
        throw new Forbidden('You can not edit all data.');
      }
    }
  }

  if (roleUrlInfo.limit &&
        (context.method === 'create' || context.method === 'update' || context.method === 'patch' ) &&
          roleUrlInfo.limit.custom) {
    const processField = (data, fieldInfo, needAddNew)=>{
      if (!fieldInfo.field) {return;}
      const currentField = _.get(data, fieldInfo.field);
      if(data.$unset){delete data.$unset[fieldInfo.field];}
      if(fieldInfo.force !== undefined){
        if (!needAddNew) {
          delete data[fieldInfo.field];
        }else if ( isObject(fieldInfo.force) && fieldInfo.force.clear) {
          delete data[fieldInfo.field];
        }else if ( isObject(fieldInfo.force) && fieldInfo.force.idField) {
          const idValue = _.get(context.params, `${fieldInfo.force.entity||'user'}.${fieldInfo.force.idField}`);

          if (idValue!==undefined) {
            _.set(data, fieldInfo.field, idValue);
          }else if(!fieldInfo.force.sparse){
            throw new GeneralError(`${fieldInfo.force.entity||'user'}.${fieldInfo.force.idField} is not existed`);
          }
        }else{
          _.set(data, fieldInfo.field, fieldInfo.force);
        }
      }else if (currentField !== undefined && fieldInfo.range) {
        const rangeValue = fieldInfo.range.map((c)=>{
          if (isObject(c) && c.idField) {
            const idValue = _.get(context.params, `${c.entity||'user'}.${c.idField}`);

            return idValue;
          }else{
            return c;
          }
        });
        if (Array.isArray( currentField )) {
          const checkAllow = currentField.every((c)=>{
            return rangeValue.includes(c);
          });
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
      }else if(currentField===undefined && fieldInfo.default !== undefined && needAddNew){
        if ( isObject(fieldInfo.default) && fieldInfo.default.idField) {
          const idValue = _.get(context.params, `${fieldInfo.default.entity||'user'}.${fieldInfo.default.idField}`);

          if (idValue!==undefined) {
            _.set(data, fieldInfo.field, idValue);
          }
        }else{
          _.set(data, fieldInfo.field, fieldInfo.default);
        }
      }

      return true;
    };

    return roleUrlInfo.limit.custom.every((fieldInfo)=>{
      if (Array.isArray(context.data)) {
        return context.data.every((data)=>{
          const dataNeed2Process=[data];
          Object.keys(data).forEach((key)=>{
            if (key.charAt(0) === '$') {
              if (key==='$set') {
                dataNeed2Process.push(data[key]);
              }else if(key==='$unset'){
              }else{
                delete data[key];
              }
            }
          });

          return dataNeed2Process.every((c, i)=>processField(c, fieldInfo, i==0));
        });
      }else{
        const dataNeed2Process=[context.data];
        Object.keys(context.data).forEach((key)=>{
          if (key.charAt(0) === '$') {
            if (key==='$set') {
              dataNeed2Process.push(context.data[key]);
            }else if(key==='$unset'){
            }else{
              delete context.data[key];
            }
          }
        });

        return dataNeed2Process.every((c, i)=>processField(c, fieldInfo, i==0));
      }
    });
    // debug('after custom', context.data);
  }

  return true;

}

module.exports = function checkPermissions (options = {}) {
  //eslint-disable-next-line no-param-reassign
  options = Object.assign({
    entity: 'user',
    field: 'permissions'
  }, options);

  const { entity: entityName, field, roles, preventEditAll=true } = options;

  return function (context) {
    return Promise.resolve(typeof roles === 'function' ? roles(context) : roles).then((currentRoles) => {
      if (context.type !== 'before') {
        return Promise.reject(new Error('The feathers-permissions hook should only be used as a \'before\' hook.'));
      }
      if (!context.rolesInfo && !Array.isArray(roles) && typeof roles !== 'function') {
        throw new Error('\'roles\' option for feathers-permissions hook must be an array or a function or must provide rolesInfo');
      }

      debug('Running checkPermissions hook with options:', options);
      const entity = context.params[entityName];
      const rolesInfo = context.rolesInfo;

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
        permissions = permissions.split(',').map((current) => current.trim());
      }

      const requiredPermissions = currentRoles;
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
        debug('Required Permissions', requiredPermissions);
        const rolePass = permissions.find((permission) => requiredPermissions.includes(permission) || requiredPermissions.includes(`${permission}:${method}`) );
        const permitted = !!rolePass;
        context.params.permitted = context.params.permitted || permitted;
        context.params.rolePass = rolePass;
      }else if(rolesInfo){
        debug('Required Permissions rolesInfo', rolesInfo);
        const rolePass = permissions.find((role)=>processRole(context, role, rolesInfo, {preventEditAll}));
        const permitted = !!rolePass;
        context.params.permitted = context.params.permitted || permitted;
        context.params.rolePass = rolePass;
      }else{
        debug('Required Permissions no requiredPermissions neither rolesInfo', rolesInfo);
      }

      if (context.params.provider && options.error !== false && !context.params.permitted) {
        throw new Forbidden('You do not have the correct permissions.');
      }

      return context;
    });
  };
};
