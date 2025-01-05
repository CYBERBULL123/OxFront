'use client'

import React from 'react'
import Layout from '../../../components/Layout'
import { motion } from 'framer-motion'
import { Image, FileText, PlayCircle, Shield, FilePlus, Cloud } from 'lucide-react'

export default function OxImaGenDocs() {
  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="max-w-4xl mx-auto"
      >
        <h2 className="text-3xl font-semibold text-gray-800 dark:text-white mb-6">
          OxImaGen Documentation <FileText className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
        </h2>
        
        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4">
            Overview <Image className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            OxImaGen is an AI-powered tool for high-quality image generation and analysis. It offers advanced parameters for creative customization, allowing users to generate images based on specific themes, art styles, resolutions, and more. Additionally, OxImaGen converts generated stories into speech and supports regional language translation.
          </p>
        </section>

        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4">
            Architecture <Cloud className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            OxImaGen is built with a robust architecture that combines cutting-edge technologies to provide a seamless image generation and analysis experience.
          </p>
          <table className="min-w-full text-left text-gray-600 dark:text-gray-400">
            <thead>
              <tr>
                <th className="px-4 py-2">Component</th>
                <th className="px-4 py-2">Technology</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="px-4 py-2">Frontend</td>
                <td className="px-4 py-2">Nextjs</td>
              </tr>
              <tr>
                <td className="px-4 py-2">Backend</td>
                <td className="px-4 py-2">Hugging Face, Google Gemini</td>
              </tr>
              <tr>
                <td className="px-4 py-2">Data Handling</td>
                <td className="px-4 py-2">Efficient Data Pipelines</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4">
            API Usage <FilePlus className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            OxImaGen leverages APIs to facilitate image generation, analysis, and story generation.
          </p>
          <table className="min-w-full text-left text-gray-600 dark:text-gray-400">
            <thead>
              <tr>
                <th className="px-4 py-2">API</th>
                <th className="px-4 py-2">Endpoint</th>
                <th className="px-4 py-2">Parameters</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="px-4 py-2">Hugging Face</td>
                <td className="px-4 py-2">/generate-image</td>
                <td className="px-4 py-2">prompt, style, resolution</td>
              </tr>
              <tr>
                <td className="px-4 py-2">Google Gemini</td>
                <td className="px-4 py-2">/analyze-image</td>
                <td className="px-4 py-2">image_url, analysis_type</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4">
            Core Functions <Shield className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
          </h3>
          <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
            <li>query_hf_model: Generates images from text prompts.</li>
            <li>get_gemini_response: Analyzes images for insights or vulnerabilities.</li>
            <li>generate_story_from_image: Generates a story based on an image.</li>
            <li>generate_image_from_story: Creates images based on a provided story.</li>
          </ul>
        </section>

        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4">
            How to Use <PlayCircle className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
          </h3>
          <ol className="list-decimal list-inside text-gray-600 dark:text-gray-400 space-y-4">
            <li><span className="font-semibold">Access OxImaGen:</span> Navigate to the OxImaGen section in your OxSuite application.</li>
            <li><span className="font-semibold">Generate or Upload Image:</span> Provide a text prompt or upload an image for analysis.</li>
            <li><span className="font-semibold">Review Image:</span> View the generated image or uploaded image after processing.</li>
            <li><span className="font-semibold">Analyze Image:</span> Request image analysis to detect potential threats or insights.</li>
            <li><span className="font-semibold">Story Generation:</span> Generate a story based on the image or vice versa.</li>
          </ol>
        </section>

        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4">
            Best Practices <Shield className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
          </h3>
          <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
            <li>Use a variety of image types for testing security measures.</li>
            <li>Integrate OxImaGen with other OxSuite tools for enhanced functionality.</li>
            <li>Regularly update AI models to ensure accurate image generation and analysis.</li>
            <li>Ensure a user-friendly experience with easy navigation and intuitive design.</li>
          </ul>
        </section>
      </motion.div>
    </Layout>
  )
}
