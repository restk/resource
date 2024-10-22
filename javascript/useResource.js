import axios from 'axios'
import { useState, createContext, useContext } from 'react';

axios.defaults.withCredentials = true

const defaultAxios = axios.create({
    baseURL: 'http://localhost:8188',
    timeout: 5000,
});

export const ResourceContext = createContext({
    axios: defaultAxios,
    resourcePath: "/resource",
});

function parseArguments(...args) {
    let resource = null;
    let subResource = null;
    let options = null;

    if (args.length > 3) {
        throw 'useResource call has a maximum of 3 args'
    }
    if (args.length == 1) {
        console.error(args)
        if (typeof args[0] !== 'string') {
            throw 'useResource call with a single argument must be a resource (string)'
        }
        resource = args[0]
    }
    if (args.length == 2) {
        if (typeof args[0] === 'string') {
            resource = args[0]

            if (typeof args[1] === 'object' && !Array.isArray(args[1]) && args[1] !== null) {
                options = args[1]
            } else if (typeof args[1] === 'string') {
                subResource = args[1]
            }
        } else {
            throw 'useResource call first argument must be a resource (string)'
        }
    }
    if (args.length == 3) {
        if (typeof args[0] !== 'string' || typeof args[1] !== 'string' || typeof args[2] !== 'object') {
            throw 'useResource call with three arguments must me in the format useGet(resource, subResourceResource, options)'
        }
        resource = args[0]
        subResource =  args[1]
        options = args[2]
    }

    return {
        resource: resource,
        subResource: subResource,
        options: options,
    }
}

function useList(...args) {
    let { resource, subResource, options } = parseArguments(...args)

    const ctx = useContext(ResourceContext);
    const [data, setData] = useState(null);
    const [loading, setIsLoading] = useState(null);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);

    // pagination
    const [page, setPage] = useState(options.page || 1);
    const [pageSize, setPageSize] = useState(options.pageSize || 25);

    const listResource = async (arg1, arg2) => {
        try {
            let filters = null;
            if (subResource !== null) {
                filters = arg2 || {};
            } else {
                filters = arg1 || {};
            }

            filters['page'] = page;
            filters['page_size'] = pageSize;

            setIsLoading(true);
            setSuccess(false);
            setError(null);

            const queryString = new URLSearchParams(filters).toString();

            let response = null;
            if (subResource !== null) {
                response = await ctx.axios.get(ctx.resourcePath + "/" + resource + "/" + arg1 + "/" + subResource + "?" + queryString);
            }  else {
                response = await ctx.axios.get(ctx.resourcePath + "/" + resource + "?" + queryString);
            }

            setData(response.data);
            setIsLoading(false);
            setSuccess(true);

        } catch (error) {
            setSuccess(false);
            setError(error);
            setIsLoading(false);
        }
    }

    return {
        fetch: listResource,

        data: data,
        loading: loading,
        error: error,
        success: success,

        // pagination
        page: page,
        setPage: setPage,
        pageSize: pageSize,
        setPageSize: setPageSize,
    }
}

function useGet(...args) {
    let { resource, subResource, options } = parseArguments(...args)
    const ctx = useContext(ResourceContext);
    const [data, setData] = useState(null);
    const [loading, setIsLoading] = useState(null);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);

    const getResource = async (arg1, arg2) => {
        try {
            setIsLoading(true);
            setSuccess(false);
            setError(null);

            let response = null;
            if (subResource !== null) {
                response = await ctx.axios.get(ctx.resourcePath + "/" + resource + "/" + arg1 + "/" + subResource + "/" + arg2);
            }  else {
                response = await ctx.axios.get(ctx.resourcePath + "/" + resource + "/" + arg1);
            }

            setData(response.data);
            setIsLoading(false);
            setSuccess(true);

        } catch (error) {
            setSuccess(false);
            setError(error);
            setIsLoading(false);
        }
    }

    return {
        fetch: getResource,

        data: data,
        loading: loading,
        error: error,
        success: success,
    }
}

function useCreate(...args) {
    let { resource, subResource, options } = parseArguments(...args)

    const ctx = useContext(ResourceContext);
    const [data, setData] = useState(null);
    const [loading, setIsLoading] = useState(null);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);

    const createResource = async (arg1, arg2) => {
        try {
            setIsLoading(true);
            setSuccess(false);
            setError(null);

            let response = null;
            if (subResource !== null) {
                response = await ctx.axios.put(ctx.resourcePath + "/" + resource + "/" + arg1 + "/" + subResource, arg2);
            }  else {
                response = await ctx.axios.put(ctx.resourcePath + "/" + resource, arg1);
            }

            setData(response.data);
            setIsLoading(false);
            setSuccess(true);
        } catch (error) {
            setError(error);
            setIsLoading(false);
        }

    }

    return {
        fetch: createResource,
        data: data,
        loading: loading,
        error: error,
        success: success,
    }
}

function useUpdate(...args) {
    let { resource, subResource, options } = parseArguments(...args)

    const ctx = useContext(ResourceContext);
    const [data, setData] = useState(null);
    const [loading, setIsLoading] = useState(null);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);

    const updateResource = async (arg1, arg2, arg3) => {
        try {
            setIsLoading(true);
            setSuccess(false);
            setError(null);

            let response = null;
            if (subResource !== null) {
                response = await ctx.axios.put(ctx.resourcePath + "/" + resource + "/" + arg1 + "/" + subResource + "/" + arg2, arg3);
            }  else {
                response = await ctx.axios.put(ctx.resourcePath + "/" + resource + "/" + arg1, arg2);
            }

            setData(response.data);
            setIsLoading(false);
            setSuccess(true);

        } catch (error) {
            setSuccess(false);
            setError(error);
            setIsLoading(false);
        }
    }

    return {
        fetch: updateResource,
        data: data,
        loading: loading,
        error: error,
        success: success,
    }
}

function usePatch(...args) {
    let { resource, subResource, options } = parseArguments(...args)

    const ctx = useContext(ResourceContext);
    const [data, setData] = useState(null);
    const [loading, setIsLoading] = useState(null);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);

    const patchResource = async (arg1, arg2, arg3) => {
        try {
            setIsLoading(true);
            setSuccess(false);
            setError(null);

            let response = null;
            if (subResource !== null) {
                response = await ctx.axios.patch(ctx.resourcePath + "/" + resource + "/" + arg1 + "/" + subResource + "/" + arg2, arg3);
            }  else {
                response = await ctx.axios.patch(ctx.resourcePath + "/" + resource + "/" + arg1, arg2);
            }

            setData(response.data);
            setIsLoading(false);
            setSuccess(true);

        } catch (error) {
            setSuccess(false);
            setError(error);
            setIsLoading(false);
        }
    }

    return {
        fetch: patchResource,
        data: data,
        loading: loading,
        error: error,
        success: success,
    }
}

function useDelete(...args) {
    let { resource, subResource, options } = parseArguments(...args)

    const ctx = useContext(ResourceContext);
    const [data, setData] = useState(null);
    const [loading, setIsLoading] = useState(null);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);

    const deleteResource = async (arg1, arg2, arg3) => {
        try {
            setIsLoading(true);
            setSuccess(false);

            let response = null;
            if (subResource !== null) {
                response = await ctx.axios.delete(ctx.resourcePath + "/" + resource + "/" + arg1 + "/" + subResource + "/" + arg2, { data: arg3 })
            }  else {
                response = await ctx.axios.delete(ctx.resourcePath + "/" + resource + "/" + arg1, { data: arg2 })
            }

            setData(response.data);
            setIsLoading(false);
            setSuccess(true);
        } catch (error) {
            setSuccess(false);
            setError(error);
            setIsLoading(false);
        }
    }

    return {
        fetch: deleteResource,

        data: data,
        loading: loading,
        error: error,
        success: success,
    }
}

function useResource(...args) {
    return {
        list: useList(...args),
        get: useGet(...args),
        create: useCreate(...args),
        update: useUpdate(...args),
        patch: usePatch(...args),
        // remove used here since delete is a reserved keyword in JavaScript
        remove: useDelete(...args),
    }
}

export default useResource;