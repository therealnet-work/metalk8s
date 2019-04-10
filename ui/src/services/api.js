import axios from 'axios';
import { Config, Core_v1Api } from '@kubernetes/client-node';

let config, coreV1;

//Basic Auth
export async function authenticate(token, api_server) {
  localStorage.removeItem('token');
  try {
    const response = await axios.get(api_server.url + '/api/v1', {
      headers: {
        Authorization: 'Basic ' + token
      }
    });
    config = new Config(api_server.url, token, 'Basic');
    coreV1 = config.makeApiClient(Core_v1Api);

    return response;
  } catch (error) {
    return { error };
  }
}

export const logout = () => {
  localStorage.removeItem('token');
};

export async function getNodes() {
  try {
    return await coreV1.listNode();
  } catch (error) {
    return { error };
  }
}

export async function getPods() {
  try {
    return await coreV1.listPodForAllNamespaces();
  } catch (error) {
    return { error };
  }
}

export async function fetchTheme() {
  try {
    return await axios.get(process.env.PUBLIC_URL + '/brand/theme.json');
  } catch (error) {
    return { error };
  }
}

export async function fetchConfig() {
  try {
    return await axios.get(process.env.PUBLIC_URL + '/config.json');
  } catch (error) {
    return { error };
  }
}

export async function createNode(payload) {
  const body = {
    metadata: {
      name: payload.name,
      annotations: {
        'metalk8s.scality.com/ssh-user': payload.ssh_user,
        'metalk8s.scality.com/ssh-port': payload.ssh_port,
        'metalk8s.scality.com/ssh-host': payload.hostName_ip,
        'metalk8s.scality.com/ssh-key-path': payload.ssh_key_path,
        'metalk8s.scality.com/ssh-sudo': payload.sudo_required.toString(),
        'metalk8s.scality.com/workload-plane': payload.workload_plane.toString(),
        'metalk8s.scality.com/control-plane': payload.control_plane.toString()
      }
    }
  };

  try {
    return await coreV1.createNode(body);
  } catch (error) {
    return { error };
  }
}
