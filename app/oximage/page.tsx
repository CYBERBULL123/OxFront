'use client'

import React, { useState } from 'react'
import Layout from '../../components/Layout'
import { motion } from 'framer-motion'
import { Upload, ImageIcon, Zap } from 'lucide-react'
import { generateImage } from '@/lib/api'

const OxImaGen: React.FC = () => {
  const [image, setImage] = useState<File | null>(null)
  const [generatedImage, setGeneratedImage] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setImage(e.target.files[0])
    }
  }

  const handleGenerate = async () => {
    if (!image) return
    setLoading(true)
    try {
      const result = await generateImage(image)
      setGeneratedImage(result)
    } catch (error) {
      console.error('Error generating image:', error)
      // Handle error (e.g., show error message to user)
    }
    setLoading(false)
  }

  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6"
      >
        <h1 className="text-3xl font-bold mb-6 text-purple-400">OxImaGen 🎨</h1>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div>
            <h2 className="text-xl font-semibold mb-4 flex items-center">
              <Upload className="mr-2 text-blue-400" size={24} />
              Upload Image
            </h2>
            <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-4 text-center">
              <input
                type="file"
                accept="image/*"
                onChange={handleImageUpload}
                className="hidden"
                id="image-upload"
              />
              <label
                htmlFor="image-upload"
                className="cursor-pointer flex flex-col items-center justify-center h-40"
              >
                <ImageIcon size={48} className="text-gray-400 mb-2" />
                <p className="text-gray-400">Click to upload or drag and drop</p>
              </label>
            </div>
            {image && (
              <p className="mt-2 text-green-400">Image uploaded: {image.name}</p>
            )}
            <button
              onClick={handleGenerate}
              disabled={!image || loading}
              className="mt-4 bg-purple-500 hover:bg-purple-600 text-white font-bold py-2 px-4 rounded-lg transition-colors duration-200 flex items-center"
            >
              <Zap className="mr-2" size={20} />
              {loading ? 'Generating...' : 'Generate'}
            </button>
          </div>
          <div>
            <h2 className="text-xl font-semibold mb-4 flex items-center">
              <ImageIcon className="mr-2 text-purple-400" size={24} />
              Generated Image
            </h2>
            {generatedImage ? (
              <img
                src={generatedImage}
                alt="Generated"
                className="w-full h-auto rounded-lg border border-gray-600"
              />
            ) : (
              <div className="bg-gray-100 dark:bg-gray-700 rounded-lg h-64 flex items-center justify-center">
                <p className="text-gray-400">Generated image will appear here</p>
              </div>
            )}
          </div>
        </div>
      </motion.div>
    </Layout>
  )
}

export default OxImaGen

