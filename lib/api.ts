import axios from 'axios'

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:5000'

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export const analyzeQuery = async (query: string): Promise<string> => {
  try {
    const response = await api.post('/analyze', { query })
    return response.data.result
  } catch (error) {
    console.error('Error in analyzeQuery:', error)
    throw error
  }
}

export const generateImage = async (image: File): Promise<string> => {
  try {
    const formData = new FormData()
    formData.append('image', image)
    const response = await api.post('/generate-image', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response.data.generatedImageUrl
  } catch (error) {
    console.error('Error in generateImage:', error)
    throw error
  }
}

export const analyzeWithLLM = async (query: string): Promise<string> => {
  try {
    const response = await api.post('/analyze-llm', { query })
    return response.data.result
  } catch (error) {
    console.error('Error in analyzeWithLLM:', error)
    throw error
  }
}

